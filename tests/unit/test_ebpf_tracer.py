"""Unit tests for app.lab.ebpf_tracer."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

from app.lab import ebpf_tracer as ebpf_module
from app.lab.ebpf_tracer import EbpfTracer


class FakeProcess:
    """Minimal stand-in for subprocess.Popen used by EbpfTracer."""

    def __init__(self, events_path: str, events: List[Dict[str, Any]]) -> None:
        self._events_path = events_path
        self._events = events
        self._emitted = False
        self._terminated = False
        self.returncode = None

    def _emit(self) -> None:
        if self._emitted:
            return
        with open(self._events_path, "w", encoding="utf-8") as fh:
            for evt in self._events:
                fh.write(json.dumps(evt) + "\n")
        self._emitted = True

    def poll(self):
        return self.returncode

    def terminate(self):
        self._terminated = True
        self.returncode = 0
        self._emit()

    def wait(self, timeout=None):
        self.returncode = 0
        self._emit()
        return 0

    def kill(self):
        self.returncode = -9
        self._emit()

    def send_signal(self, sig):
        self.returncode = -sig
        self._emit()


@pytest.mark.unit
def test_auto_backend_prefers_tetragon(monkeypatch):
    def fake_which(name):
        if name == "tetra":
            return "/usr/bin/tetra"
        if name == "tracee":
            return "/usr/bin/tracee"
        return None

    monkeypatch.delenv("SHESHNAAG_TETRAGON_BIN", raising=False)
    monkeypatch.delenv("SHESHNAAG_TRACEE_BIN", raising=False)
    monkeypatch.setattr(ebpf_module.shutil, "which", fake_which)

    tracer = EbpfTracer(backend="auto")
    assert tracer.backend == "tetragon"
    h = tracer.health()
    assert h["healthy"] is True
    assert h["backend"] == "tetragon"
    assert h["binary"] == "/usr/bin/tetra"


@pytest.mark.unit
def test_auto_backend_falls_back_to_tracee(monkeypatch):
    def fake_which(name):
        if name in ("tetra", "tetragon"):
            return None
        if name == "tracee":
            return "/usr/bin/tracee"
        return None

    monkeypatch.delenv("SHESHNAAG_TETRAGON_BIN", raising=False)
    monkeypatch.delenv("SHESHNAAG_TRACEE_BIN", raising=False)
    monkeypatch.setattr(ebpf_module.shutil, "which", fake_which)

    tracer = EbpfTracer(backend="auto")
    assert tracer.backend == "tracee"


@pytest.mark.unit
def test_missing_backend_none_mode(monkeypatch):
    monkeypatch.delenv("SHESHNAAG_TETRAGON_BIN", raising=False)
    monkeypatch.delenv("SHESHNAAG_TRACEE_BIN", raising=False)
    monkeypatch.setattr(ebpf_module.shutil, "which", lambda _: None)

    tracer = EbpfTracer(backend="auto")
    assert tracer.backend == "none"
    h = tracer.health()
    assert h["healthy"] is False

    session_id = tracer.start(target={"container_id": "abc"})
    assert session_id.startswith("ebpf-")
    events = tracer.stop(session_id)
    assert events == []


@pytest.mark.unit
def test_explicit_none_backend(monkeypatch):
    monkeypatch.setattr(ebpf_module.shutil, "which", lambda _: "/usr/bin/tetra")
    tracer = EbpfTracer(backend="none")
    assert tracer.backend == "none"
    assert tracer.health()["healthy"] is False


@pytest.mark.unit
def test_invalid_backend_raises():
    with pytest.raises(ValueError):
        EbpfTracer(backend="bogus")


@pytest.mark.unit
def test_start_stop_roundtrip_tetragon(monkeypatch):
    monkeypatch.delenv("SHESHNAAG_TETRAGON_BIN", raising=False)
    monkeypatch.delenv("SHESHNAAG_TRACEE_BIN", raising=False)
    monkeypatch.setattr(
        ebpf_module.shutil,
        "which",
        lambda name: "/usr/bin/tetra" if name == "tetra" else None,
    )

    events = [
        {
            "time": "2026-04-24T10:00:00Z",
            "process_exec": {
                "process": {"pid": 1234, "binary": "/bin/ls"},
                "parent": {"pid": 1000},
            },
        },
        {
            "time": "2026-04-24T10:00:01Z",
            "process_kprobe": {
                "process": {"pid": 1234, "binary": "/bin/ls"},
                "parent": {"pid": 1000},
                "function_name": "sys_openat",
                "args": [{"value": "/etc/passwd"}],
                "policy_name": "alert-sensitive-read",
            },
        },
    ]

    captured_argv: List[List[str]] = []

    def fake_popen(argv, stdout, stderr, start_new_session):
        captured_argv.append(list(argv))
        # stdout is the open file handle for the events path.
        events_path = stdout.name
        stdout.close()
        return FakeProcess(events_path, events)

    monkeypatch.setattr(ebpf_module.subprocess, "Popen", fake_popen)

    tracer = EbpfTracer(backend="auto")
    assert tracer.backend == "tetragon"
    session_id = tracer.start(target={"container_id": "container-abc"})
    assert session_id

    # Verify the argv Tetragon was invoked with.
    assert captured_argv
    argv = captured_argv[0]
    assert argv[0] == "/usr/bin/tetra"
    assert "getevents" in argv
    assert "--pod" in argv and "container-abc" in argv

    parsed = tracer.stop(session_id)
    assert len(parsed) == 2
    assert parsed[0]["event_type"] == "process_exec"
    assert parsed[0]["pid"] == 1234
    assert parsed[0]["ppid"] == 1000
    assert parsed[0]["backend"] == "tetragon"
    assert parsed[1]["syscall"] == "sys_openat"
    assert parsed[1]["verdict"] == "alert-sensitive-read"


@pytest.mark.unit
def test_start_stop_roundtrip_tracee(monkeypatch):
    monkeypatch.delenv("SHESHNAAG_TETRAGON_BIN", raising=False)
    monkeypatch.delenv("SHESHNAAG_TRACEE_BIN", raising=False)
    monkeypatch.setattr(
        ebpf_module.shutil,
        "which",
        lambda name: "/usr/bin/tracee" if name == "tracee" else None,
    )

    events = [
        {
            "timestamp": 1700000000.1,
            "processId": 501,
            "parentProcessId": 1,
            "processName": "sh",
            "eventName": "execve",
            "args": [{"name": "pathname", "value": "/bin/sh"}],
            "returnValue": 0,
        }
    ]

    def fake_popen(argv, stdout, stderr, start_new_session):
        events_path = stdout.name
        stdout.close()
        assert argv[0] == "/usr/bin/tracee"
        assert "--output" in argv and "json" in argv
        return FakeProcess(events_path, events)

    monkeypatch.setattr(ebpf_module.subprocess, "Popen", fake_popen)

    tracer = EbpfTracer(backend="tracee")
    assert tracer.backend == "tracee"
    session_id = tracer.start(target={"pid": 501})
    parsed = tracer.stop(session_id)

    assert len(parsed) == 1
    evt = parsed[0]
    assert evt["backend"] == "tracee"
    assert evt["pid"] == 501
    assert evt["comm"] == "sh"
    assert evt["event_type"] == "execve"
    assert evt["verdict"] == 0


@pytest.mark.unit
def test_stop_unknown_session_returns_empty(monkeypatch):
    monkeypatch.setattr(ebpf_module.shutil, "which", lambda _: None)
    tracer = EbpfTracer(backend="none")
    assert tracer.stop("does-not-exist") == []


@pytest.mark.unit
def test_popen_failure_is_graceful(monkeypatch):
    monkeypatch.setattr(
        ebpf_module.shutil,
        "which",
        lambda name: "/usr/bin/tetra" if name == "tetra" else None,
    )

    def fake_popen(*args, **kwargs):
        raise OSError("cannot exec")

    monkeypatch.setattr(ebpf_module.subprocess, "Popen", fake_popen)

    tracer = EbpfTracer(backend="tetragon")
    session_id = tracer.start(target={"container_id": "abc"})
    assert session_id
    assert tracer.stop(session_id) == []
