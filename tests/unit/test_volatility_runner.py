"""Unit tests for app.lab.volatility_runner."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import List

import pytest

from app.lab import volatility_runner as vol_module
from app.lab.volatility_runner import (
    DEFAULT_LINUX_PLUGINS,
    DEFAULT_WINDOWS_PLUGINS,
    VolatilityRunner,
)


def _touch(path: Path, text: str = "dump") -> str:
    path.write_text(text)
    return str(path)


@pytest.mark.unit
def test_health_reports_unhealthy_when_binary_missing(monkeypatch):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: None)
    runner = VolatilityRunner(vol_binary="vol-absent-xyz")
    health = runner.health()
    assert health["healthy"] is False
    assert health["reason"] == "binary_not_found"
    assert health["resolved_path"] is None
    assert health["version"] is None


@pytest.mark.unit
def test_health_reports_healthy_with_version(monkeypatch):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Volatility 3 Framework 2.5.2\nusage: vol [options] plugin",
            stderr="",
        )

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)
    runner = VolatilityRunner(vol_binary="vol")
    health = runner.health()
    assert health["healthy"] is True
    assert health["version"] == "2.5.2"
    assert health["resolved_path"] == "/usr/local/bin/vol"


@pytest.mark.unit
def test_run_returns_empty_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: None)
    dump = _touch(tmp_path / "memory.raw")
    runner = VolatilityRunner(vol_binary="vol-absent-xyz")
    assert runner.run(memory_dump_path=dump) == []


@pytest.mark.unit
def test_run_returns_empty_when_dump_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    runner = VolatilityRunner(vol_binary="vol")
    assert runner.run(memory_dump_path=str(tmp_path / "missing.raw")) == []


@pytest.mark.unit
def test_run_non_zero_exit_is_graceful(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            args=cmd, returncode=2, stdout="", stderr="boom"
        )

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)
    runner = VolatilityRunner(plugins=["windows.pslist"])
    findings = runner.run(memory_dump_path=dump)
    assert findings == []


@pytest.mark.unit
def test_run_parses_each_plugin_output(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    plugin_outputs = {
        "windows.pslist": [
            {"PID": 4, "ProcessName": "System", "ImageFileName": "System"},
            {"PID": 1234, "ProcessName": "evil.exe", "ImageFileName": "evil.exe"},
        ],
        "windows.malfind": [
            {"PID": 1234, "Process": "evil.exe", "VadStart": "0x10000"},
        ],
        "windows.netscan": [
            {
                "PID": 1234,
                "State": "ESTABLISHED",
                "ForeignAddr": "203.0.113.9",
                "ForeignPort": 443,
            }
        ],
        "windows.cmdline": [
            {"PID": 1234, "Process": "powershell", "Args": "powershell -enc ZQBjAGgA"}
        ],
        "windows.hollowfind": [
            {"PID": 1234, "Process": "svchost.exe", "Notes": "hollowed"}
        ],
        "windows.modscan": [
            {"Name": "C:\\Users\\Public\\foo.sys", "Offset": "0x1"}
        ],
    }

    def fake_run(cmd, capture_output, text, timeout):
        # cmd = [vol, -f, dump, --renderer=json, plugin]
        plugin = cmd[-1]
        out = json.dumps(plugin_outputs.get(plugin, []))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)

    runner = VolatilityRunner()
    findings = runner.run(memory_dump_path=dump, os_hint="windows")

    # Every plugin contributed at least one finding.
    plugins_seen = {f["plugin"] for f in findings}
    assert plugins_seen == set(DEFAULT_WINDOWS_PLUGINS)

    for f in findings:
        assert f["finding_type"].startswith("memory:")
        assert 0.0 <= f["confidence"] <= 1.0
        assert "payload" in f and "row" in f["payload"]


@pytest.mark.unit
def test_confidence_derivation_hits_vs_baseline(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    def fake_run(cmd, capture_output, text, timeout):
        plugin = cmd[-1]
        if plugin == "windows.pslist":
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=json.dumps([{"PID": 4, "ProcessName": "System"}]),
                stderr="",
            )
        if plugin == "windows.hollowfind":
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=json.dumps([{"PID": 1000, "Process": "svchost.exe"}]),
                stderr="",
            )
        if plugin == "windows.malfind":
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=json.dumps([{"PID": 1000, "Process": "inj.exe"}]),
                stderr="",
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)

    runner = VolatilityRunner(plugins=["windows.pslist", "windows.hollowfind", "windows.malfind"])
    findings = runner.run(memory_dump_path=dump)

    by_plugin = {f["plugin"]: f for f in findings}
    assert by_plugin["windows.pslist"]["confidence"] == pytest.approx(0.3)
    assert by_plugin["windows.hollowfind"]["confidence"] >= 0.95 - 1e-9
    assert by_plugin["windows.malfind"]["confidence"] >= 0.85
    assert by_plugin["windows.hollowfind"]["severity"] == "critical"
    assert by_plugin["windows.malfind"]["severity"] == "high"
    assert by_plugin["windows.pslist"]["severity"] == "info"


@pytest.mark.unit
def test_linux_os_hint_switches_default_plugin_catalog(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    invoked: List[str] = []

    def fake_run(cmd, capture_output, text, timeout):
        invoked.append(cmd[-1])
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)

    runner = VolatilityRunner()
    runner.run(memory_dump_path=dump, os_hint="linux")
    assert invoked == DEFAULT_LINUX_PLUGINS


@pytest.mark.unit
def test_timeout_is_graceful(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    def fake_run(cmd, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)
    runner = VolatilityRunner(plugins=["windows.pslist"])
    assert runner.run(memory_dump_path=dump) == []


@pytest.mark.unit
def test_env_var_overrides_binary(monkeypatch):
    monkeypatch.setenv("SHESHNAAG_VOLATILITY_BIN", "/opt/vol/bin/vol")
    runner = VolatilityRunner()
    assert runner.vol_binary == "/opt/vol/bin/vol"


@pytest.mark.unit
def test_dry_run_skips_subprocess(monkeypatch, tmp_path):
    monkeypatch.setattr(vol_module.shutil, "which", lambda _: "/usr/local/bin/vol")
    dump = _touch(tmp_path / "memory.raw")

    def fake_run(*args, **kwargs):
        raise AssertionError("subprocess.run must not be called in dry_run mode")

    monkeypatch.setattr(vol_module.subprocess, "run", fake_run)
    runner = VolatilityRunner(dry_run=True, plugins=["windows.pslist"])
    assert runner.run(memory_dump_path=dump) == []
