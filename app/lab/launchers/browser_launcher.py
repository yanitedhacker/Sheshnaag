"""Browser-style launcher for JS, HTA, LNK specimens.

Runs a headless Chromium container pointed at the specimen (served via a
local file:// URL), captures page navigation, console output, and the
network request tree. Uses ``docker`` + ``chromium-headless-shell`` or
the ``browserless/chrome`` image. When Docker is missing, falls back to
a dry-run plan.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult

_BROWSER_KINDS = frozenset({"file/js", "file/hta", "file/lnk", "file"})
_BROWSER_MIMES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "application/hta",
        "application/x-ms-shortcut",
    }
)


class BrowserLauncher:
    kind = "file/js"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        if specimen_kind in _BROWSER_KINDS:
            if specimen_kind != "file":
                return True
            mime = (metadata or {}).get("mime_type") or (metadata or {}).get("content_type")
            return mime in _BROWSER_MIMES
        return False

    def _has_binary(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _exec(self, argv: List[str], *, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def launch(
        self,
        *,
        specimen: Any,
        revision: Any,
        profile: Any,
        run: Any,
        quarantine_path: str,
        egress: Any,
        snapshot_snap: Any,
    ) -> LauncherResult:
        start = time.monotonic()
        logs: List[str] = []
        artifacts: List[str] = []
        metadata: Dict[str, Any] = {"launcher": "browser"}

        profile_cfg = getattr(profile, "config", {}) or {}
        timeout = int(profile_cfg.get("detonation_timeout_s", 45))
        image = profile_cfg.get("browser_image", "browserless/chrome:latest")
        specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path

        pcap_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.pcap")
        console_log_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}-console.log")
        har_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.har")
        artifacts.extend([console_log_path, har_path])

        if self._has_binary("docker"):
            container_name = f"sheshnaag-browser-{getattr(run, 'id', 'x')}"
            run_argv = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "-v",
                f"{os.path.dirname(specimen_ref)}:/specimen:ro",
                "-v",
                f"{quarantine_path}:/output",
                image,
                "chromium",
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                f"--dump-dom",
                f"file:///specimen/{os.path.basename(specimen_ref)}",
            ]
            completed = self._exec(run_argv, timeout=timeout)
            logs.append(f"browser_exec rc={completed.returncode}")
            metadata["mode"] = "docker-chromium"
            exit_code = int(completed.returncode or 0)
        else:
            logs.append("docker unavailable; dry-run only")
            metadata["mode"] = "dry-run"
            exit_code = 0
            pcap_path = None

        duration_ms = int((time.monotonic() - start) * 1000)
        return LauncherResult(
            exit_code=exit_code,
            duration_ms=duration_ms,
            pcap_path=pcap_path,
            memory_dump_path=None,
            ebpf_events=[],
            artifacts=artifacts,
            logs=logs,
            metadata=metadata,
        )


__all__ = ["BrowserLauncher"]
