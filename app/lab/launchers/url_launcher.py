"""URL launcher.

Drives a headless Chromium browser *through* a ``mitmproxy`` subprocess
so every request (including TLS-terminated bodies) is captured into the
run transcript. The mitmproxy CA cert is pre-injected into the browser
container. All external binaries are invoked via :mod:`subprocess.run`
so the launcher is trivially mockable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult


class UrlLauncher:
    kind = "url"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        return specimen_kind == "url"

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

    def _popen(self, argv: List[str]) -> subprocess.Popen:
        return subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
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
        metadata: Dict[str, Any] = {"launcher": "url"}

        profile_cfg = getattr(profile, "config", {}) or {}
        timeout = int(profile_cfg.get("detonation_timeout_s", 45))
        target_url = getattr(revision, "content_ref", None) or ""
        metadata["target_url"] = target_url

        pcap_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.pcap")
        flows_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.flows")
        screenshot_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.png")
        artifacts.extend([flows_path, screenshot_path])

        mitm = None
        if self._has_binary("mitmdump"):
            mitm = self._popen([
                "mitmdump",
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                "8081",
                "-w",
                flows_path,
            ])
            logs.append(f"mitmdump pid={mitm.pid}")
            metadata["mitm"] = True
        else:
            logs.append("mitmdump missing; recording without TLS inspection")
            metadata["mitm"] = False

        try:
            if self._has_binary("docker"):
                container_name = f"sheshnaag-url-{getattr(run, 'id', 'x')}"
                completed = self._exec(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        container_name,
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        "-e",
                        "HTTPS_PROXY=http://host.docker.internal:8081",
                        "-e",
                        "HTTP_PROXY=http://host.docker.internal:8081",
                        "-v",
                        f"{quarantine_path}:/output",
                        (profile_cfg.get("browser_image", "browserless/chrome:latest")),
                        "chromium",
                        "--headless=new",
                        "--no-sandbox",
                        "--disable-gpu",
                        f"--screenshot=/output/{os.path.basename(screenshot_path)}",
                        target_url,
                    ],
                    timeout=timeout,
                )
                logs.append(f"browser rc={completed.returncode}")
                metadata["mode"] = "docker-chromium"
                exit_code = int(completed.returncode or 0)
            else:
                logs.append("docker unavailable; dry-run only")
                metadata["mode"] = "dry-run"
                exit_code = 0
                pcap_path = None
        finally:
            if mitm is not None:
                try:
                    mitm.terminate()
                    mitm.wait(timeout=5)
                except Exception:  # pragma: no cover — tear-down best effort
                    try:
                        mitm.kill()
                    except Exception:
                        pass

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


__all__ = ["UrlLauncher"]
