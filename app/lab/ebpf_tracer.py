"""eBPF syscall tracing adapter for Tetragon / Tracee.

Provides a minimal façade that:

* Auto-detects which of ``tetra`` (Tetragon CLI) or ``tracee`` is on ``PATH``.
* Spawns a child process that emits JSON events into a temp file until the
  runner calls :meth:`stop`.
* Parses the recorded events into a canonical shape that the run-wide timeline
  stream (Redis Streams → SSE) can consume.

The tracer is best-effort: if neither backend is available, :meth:`start`
returns a session_id anyway and :meth:`stop` returns an empty event list.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SUPPORTED_BACKENDS = ("auto", "tetragon", "tracee", "none")


class EbpfTracer:
    """Runs Tetragon or Tracee and normalizes their JSON event streams."""

    def __init__(
        self,
        *,
        backend: str = "auto",
        config_path: Optional[str] = None,
    ) -> None:
        if backend not in _SUPPORTED_BACKENDS:
            raise ValueError(f"backend must be one of {_SUPPORTED_BACKENDS}, got {backend!r}")
        self.requested_backend = backend
        self.config_path = config_path
        self.backend, self._binary_path = self._resolve_backend(backend)
        self._sessions: Dict[str, Dict[str, Any]] = {}

    # -- Backend resolution ---------------------------------------------------

    @staticmethod
    def _tetragon_binary() -> Optional[str]:
        override = os.environ.get("SHESHNAAG_TETRAGON_BIN")
        if override and os.path.exists(override):
            return override
        if override:
            return shutil.which(override)
        return shutil.which("tetra") or shutil.which("tetragon")

    @staticmethod
    def _tracee_binary() -> Optional[str]:
        override = os.environ.get("SHESHNAAG_TRACEE_BIN")
        if override and os.path.exists(override):
            return override
        if override:
            return shutil.which(override)
        return shutil.which("tracee") or shutil.which("tracee-ebpf")

    @classmethod
    def _resolve_backend(cls, backend: str) -> tuple[str, Optional[str]]:
        if backend == "none":
            return "none", None
        if backend == "tetragon":
            path = cls._tetragon_binary()
            return ("tetragon", path) if path else ("none", None)
        if backend == "tracee":
            path = cls._tracee_binary()
            return ("tracee", path) if path else ("none", None)
        # auto
        tetra = cls._tetragon_binary()
        if tetra:
            return "tetragon", tetra
        tracee = cls._tracee_binary()
        if tracee:
            return "tracee", tracee
        return "none", None

    # -- Health ---------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        return {
            "tool": "ebpf_tracer",
            "requested_backend": self.requested_backend,
            "backend": self.backend,
            "binary": self._binary_path,
            "healthy": self.backend != "none",
            "reason": None if self.backend != "none" else "no_supported_backend_on_path",
            "active_sessions": list(self._sessions.keys()),
        }

    # -- Lifecycle ------------------------------------------------------------

    def start(self, *, target: Dict[str, Any]) -> str:
        """Start a tracing session bound to ``target``.

        ``target`` may contain any of::

            {"container_id": "abc123"}
            {"pid": 1234}
            {"netns": "/var/run/netns/foo"}

        When the resolved backend is ``none`` a synthetic session id is still
        returned so that callers can unconditionally call :meth:`stop`.
        """
        session_id = f"ebpf-{uuid.uuid4().hex[:12]}"
        events_file = tempfile.NamedTemporaryFile(
            prefix=f"sheshnaag-{session_id}-",
            suffix=".jsonl",
            delete=False,
        )
        events_path = events_file.name
        events_file.close()
        session: Dict[str, Any] = {
            "session_id": session_id,
            "backend": self.backend,
            "target": dict(target or {}),
            "events_path": events_path,
            "started_at": time.time(),
            "proc": None,
            "argv": None,
            "stopped": False,
        }

        if self.backend == "none" or not self._binary_path:
            self._sessions[session_id] = session
            logger.info(
                "ebpf_tracer: starting no-op session %s (backend=%s)",
                session_id,
                self.backend,
            )
            return session_id

        argv = self._build_argv(target or {})
        session["argv"] = argv
        try:
            handle = open(events_path, "w", encoding="utf-8")
        except OSError as exc:
            logger.warning("ebpf_tracer: cannot open events file %s: %s", events_path, exc)
            self._sessions[session_id] = session
            return session_id

        try:
            proc = subprocess.Popen(
                argv,
                stdout=handle,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("ebpf_tracer: failed to spawn %s: %s", argv[0] if argv else "?", exc)
            handle.close()
            self._sessions[session_id] = session
            return session_id

        session["proc"] = proc
        session["stdout_handle"] = handle
        self._sessions[session_id] = session
        return session_id

    def stop(self, session_id: str) -> List[Dict[str, Any]]:
        """Terminate the session identified by ``session_id`` and parse events."""
        session = self._sessions.get(session_id)
        if session is None:
            logger.warning("ebpf_tracer: unknown session %s", session_id)
            return []
        if session.get("stopped"):
            return self._parse_events(session)

        proc: Optional[subprocess.Popen] = session.get("proc")
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("ebpf_tracer: terminate failed for %s: %s", session_id, exc)
                try:
                    proc.send_signal(signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass

        handle = session.get("stdout_handle")
        if handle is not None:
            try:
                handle.flush()
            except (OSError, ValueError):
                pass
            try:
                handle.close()
            except (OSError, ValueError):
                pass
            session["stdout_handle"] = None

        session["stopped"] = True
        session["ended_at"] = time.time()
        events = self._parse_events(session)

        # Best-effort cleanup of the scratch file.
        events_path = session.get("events_path")
        if events_path and os.path.exists(events_path):
            try:
                os.unlink(events_path)
            except OSError:
                pass
        return events

    # -- Internals ------------------------------------------------------------

    def _build_argv(self, target: Dict[str, Any]) -> List[str]:
        binary = self._binary_path
        if not binary:
            return []
        if self.backend == "tetragon":
            argv = [binary, "getevents", "-o", "json"]
            if self.config_path:
                argv.extend(["--config", self.config_path])
            container_id = target.get("container_id")
            if container_id:
                argv.extend(["--pod", str(container_id)])
            pid = target.get("pid")
            if pid:
                argv.extend(["--pid", str(pid)])
            return argv
        if self.backend == "tracee":
            argv = [binary, "--output", "json"]
            if self.config_path:
                argv.extend(["--config", self.config_path])
            container_id = target.get("container_id")
            if container_id:
                argv.extend(["--scope", f"container={container_id}"])
            pid = target.get("pid")
            if pid:
                argv.extend(["--scope", f"pid={pid}"])
            netns = target.get("netns")
            if netns:
                argv.extend(["--scope", f"mntns={netns}"])
            return argv
        return []

    def _parse_events(self, session: Dict[str, Any]) -> List[Dict[str, Any]]:
        events_path = session.get("events_path")
        if not events_path or not os.path.exists(events_path):
            return []
        try:
            with open(events_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            logger.warning("ebpf_tracer: failed to read %s: %s", events_path, exc)
            return []
        if not text.strip():
            return []

        raw_events: List[Dict[str, Any]] = []
        # Tetragon/Tracee both emit JSON-lines, but be tolerant of a single
        # JSON array too.
        stripped = text.strip()
        parsed_full = None
        if stripped.startswith("["):
            try:
                parsed_full = json.loads(stripped)
            except json.JSONDecodeError:
                parsed_full = None
        if isinstance(parsed_full, list):
            for item in parsed_full:
                if isinstance(item, dict):
                    raw_events.append(item)
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    raw_events.append(obj)

        backend = session.get("backend", self.backend)
        return [self._normalize_event(evt, backend) for evt in raw_events]

    @staticmethod
    def _normalize_event(event: Dict[str, Any], backend: str) -> Dict[str, Any]:
        """Canonicalize a raw event into the Sheshnaag timeline shape."""
        if backend == "tetragon":
            # Tetragon events look like {"process_kprobe": {...}, "node_name": ...}
            known_keys = (
                "process_exec",
                "process_kprobe",
                "process_exit",
                "process_tracepoint",
            )
            event_type = next((key for key in known_keys if key in event), "unknown")
            body = event.get(event_type, {}) if isinstance(event.get(event_type), dict) else {}
            proc = body.get("process") or {}
            parent = body.get("parent") or {}
            return {
                "ts": body.get("time") or event.get("time"),
                "pid": _coerce_int(proc.get("pid")),
                "ppid": _coerce_int(parent.get("pid")),
                "comm": proc.get("binary") or proc.get("exec_id") or proc.get("pod", {}).get("name"),
                "event_type": event_type,
                "syscall": body.get("function_name"),
                "args": body.get("args") or proc.get("arguments"),
                "verdict": body.get("policy_name") or body.get("action"),
                "backend": "tetragon",
                "raw": event,
            }
        if backend == "tracee":
            # Tracee output shape (v0.20+): top-level keys include eventName,
            # processName, pid, processId, hostProcessId, args, returnValue.
            return {
                "ts": event.get("timestamp") or event.get("time"),
                "pid": _coerce_int(event.get("processId") or event.get("pid")),
                "ppid": _coerce_int(event.get("parentProcessId") or event.get("ppid")),
                "comm": event.get("processName") or event.get("comm"),
                "event_type": event.get("eventName") or "syscall",
                "syscall": event.get("eventName") or event.get("syscall"),
                "args": event.get("args"),
                "verdict": event.get("returnValue"),
                "backend": "tracee",
                "raw": event,
            }
        # Unknown backend — return as-is under a stable envelope.
        return {
            "ts": event.get("ts") or event.get("time") or event.get("timestamp"),
            "pid": _coerce_int(event.get("pid")),
            "ppid": _coerce_int(event.get("ppid")),
            "comm": event.get("comm") or event.get("process"),
            "event_type": event.get("event_type") or "unknown",
            "syscall": event.get("syscall"),
            "args": event.get("args"),
            "verdict": event.get("verdict"),
            "backend": backend or "unknown",
            "raw": event,
        }


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
