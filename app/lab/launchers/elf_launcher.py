"""ELF / shell-script launcher.

Reuses the hardening primitives baked into
``app/lab/docker_kali_provider.py`` — notably ``--cap-drop ALL``,
``--read-only``, ``--security-opt=no-new-privileges``. The specimen is
mounted read-only into a Kali container, executed via ``docker exec``,
and telemetry is collected by the eBPF tracer and pcap tap that the
caller already attached.

On hosts without Docker (the macOS development loop) the launcher emits
a dry-run plan.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult

_ELF_KINDS = frozenset({"file/elf", "file/script", "file"})
_ELF_MIMES = frozenset(
    {
        "application/x-executable",
        "application/x-sharedlib",
        "application/x-pie-executable",
        "text/x-shellscript",
        "application/x-shellscript",
        "application/x-python",
        "application/x-perl",
    }
)


class ElfLauncher:
    kind = "file/elf"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        if specimen_kind in _ELF_KINDS:
            if specimen_kind != "file":
                return True
            mime = (metadata or {}).get("mime_type") or (metadata or {}).get("content_type")
            return mime in _ELF_MIMES
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
        metadata: Dict[str, Any] = {"launcher": "elf"}

        profile_cfg = getattr(profile, "config", {}) or {}
        timeout = int(profile_cfg.get("detonation_timeout_s", 60))
        image = profile_cfg.get("container_image", "kalilinux/kali-rolling:latest")
        specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path
        inner = f"/specimen/{os.path.basename(specimen_ref)}"

        pcap_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.pcap")

        if self._has_binary("docker"):
            container_name = f"sheshnaag-elf-{getattr(run, 'id', 'x')}"
            run_argv = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "-v",
                f"{os.path.dirname(specimen_ref)}:/specimen:ro",
                image,
                "sh",
                "-c",
                f"chmod +x {inner} && {inner}",
            ]
            completed = self._exec(run_argv, timeout=timeout)
            logs.append(f"docker_run rc={completed.returncode}")
            metadata["mode"] = "docker"
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


__all__ = ["ElfLauncher"]
