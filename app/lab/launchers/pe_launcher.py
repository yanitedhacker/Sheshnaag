"""PE / MSI launcher.

Real path: libvirt-managed Windows VM. The VM's snapshot is created and
reverted by :class:`app.lab.snapshot_manager.SnapshotManager`; this
launcher only *drives* the guest. Execution happens via one of
``winexe`` / ``psexec.py`` / WMI over ``wmic``. The specimen is staged
through a virtio-9p shared folder rooted at ``quarantine_path``.

Dev / CI path: when ``virsh`` is missing (macOS development, sandboxed
CI) the launcher falls back to a ``wine`` container dry-run. In both
paths every external binary is invoked through :mod:`subprocess.run`,
which makes the class trivial to mock — tests patch
``subprocess.run`` and inspect the call sites.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult

# PE-ish specimen kinds. We accept the legacy ``file`` kind too because
# the V3 schema stores all binary specimens as ``file`` and leans on
# ``metadata["mime_type"]`` for differentiation.
_PE_KINDS = frozenset({"file/pe", "file/msi", "file"})
_PE_MIMES = frozenset(
    {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
        "application/x-msi",
        "application/x-msdos-program",
    }
)


class PeLauncher:
    kind = "file/pe"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        if specimen_kind in _PE_KINDS:
            mime = (metadata or {}).get("mime_type") or (metadata or {}).get("content_type")
            # Explicit PE-ish kind always matches. Generic ``file`` only
            # matches when the mime looks PE-like.
            if specimen_kind != "file":
                return True
            return mime in _PE_MIMES
        return False

    # ------------------------------------------------------------------

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
        metadata: Dict[str, Any] = {"launcher": "pe"}

        duration_target = int((getattr(profile, "config", {}) or {}).get("detonation_timeout_s", 120))
        guest_name = (getattr(profile, "config", {}) or {}).get("vm_name", "sheshnaag-win-detonation")

        pcap_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.pcap")
        memdump_path = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.mem")

        real_mode = self._has_binary("virsh")
        if real_mode:
            logs.append(f"virsh present: booting guest {guest_name}")
            self._exec(["virsh", "start", guest_name], timeout=30)
            specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path
            # Dispatch via winexe if available, else fall back to wmic.
            if self._has_binary("winexe"):
                exec_argv = [
                    "winexe",
                    "-U",
                    (getattr(profile, "config", {}) or {}).get("guest_creds", "Analyst%analyst"),
                    f"//{guest_name}",
                    f"cmd.exe /c \"C:\\\\stage\\\\{os.path.basename(specimen_ref)}\"",
                ]
            elif self._has_binary("psexec.py"):
                exec_argv = [
                    "psexec.py",
                    (getattr(profile, "config", {}) or {}).get("guest_creds", "Analyst:analyst") + f"@{guest_name}",
                    f"C:\\stage\\{os.path.basename(specimen_ref)}",
                ]
            else:
                exec_argv = [
                    "wmic",
                    "/node:" + guest_name,
                    "process",
                    "call",
                    "create",
                    f"C:\\stage\\{os.path.basename(specimen_ref)}",
                ]
            completed = self._exec(exec_argv, timeout=duration_target)
            logs.append(f"guest_exec rc={completed.returncode}")
            self._exec(["virsh", "dump", "--memory-only", guest_name, memdump_path], timeout=60)
            artifacts.append(memdump_path)
            metadata["mode"] = "libvirt"
            exit_code = int(completed.returncode or 0)
        elif self._has_binary("docker"):
            logs.append("virsh missing; falling back to wine container")
            container_name = f"sheshnaag-wine-{getattr(run, 'id', 'x')}"
            specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path
            completed = self._exec(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    container_name,
                    "--network",
                    "none",
                    "--cap-drop",
                    "ALL",
                    "-v",
                    f"{quarantine_path}:/quarantine:ro",
                    "scottyhardy/docker-wine:latest",
                    "wine",
                    f"/quarantine/{os.path.basename(specimen_ref)}",
                ],
                timeout=duration_target,
            )
            logs.append(f"wine_exec rc={completed.returncode}")
            metadata["mode"] = "wine-docker"
            exit_code = int(completed.returncode or 0)
        else:
            logs.append("no virsh, no docker — emitting dry-run plan")
            metadata["mode"] = "dry-run"
            exit_code = 0
            # No real pcap/memory dump in dry-run.
            pcap_path = None
            memdump_path = None

        duration_ms = int((time.monotonic() - start) * 1000)
        return LauncherResult(
            exit_code=exit_code,
            duration_ms=duration_ms,
            pcap_path=pcap_path,
            memory_dump_path=memdump_path,
            ebpf_events=[],
            artifacts=artifacts,
            logs=logs,
            metadata=metadata,
        )


__all__ = ["PeLauncher"]
