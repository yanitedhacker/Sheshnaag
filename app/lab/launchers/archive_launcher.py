"""Archive launcher (zip / rar / 7z / iso).

Unpacks under the run's quarantine directory, then emits every extracted
child as an artifact. Recursive dispatch into
:func:`dispatch_launcher` is the service-layer's job; this launcher
only surfaces children.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import zipfile
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult

_ARCHIVE_KINDS = frozenset(
    {"archive/zip", "archive/rar", "archive/7z", "archive/iso", "archive"}
)


class ArchiveLauncher:
    kind = "archive/zip"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        return specimen_kind in _ARCHIVE_KINDS

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

    def _extract(self, archive_path: str, dest: str, ext: str, timeout: int, logs: List[str]) -> int:
        os.makedirs(dest, exist_ok=True)
        if ext == ".zip":
            try:
                with zipfile.ZipFile(archive_path) as zf:
                    zf.extractall(dest)
                logs.append(f"zipfile extracted -> {dest}")
                return 0
            except Exception as exc:  # pragma: no cover — fallback below
                logs.append(f"zipfile failed: {exc}; falling back to unzip")
        if ext == ".rar" and self._has_binary("unrar"):
            cp = self._exec(["unrar", "x", "-o+", archive_path, dest + "/"], timeout=timeout)
            logs.append(f"unrar rc={cp.returncode}")
            return int(cp.returncode or 0)
        if ext == ".7z" and self._has_binary("7z"):
            cp = self._exec(["7z", "x", f"-o{dest}", archive_path, "-y"], timeout=timeout)
            logs.append(f"7z rc={cp.returncode}")
            return int(cp.returncode or 0)
        if ext == ".iso" and self._has_binary("7z"):
            cp = self._exec(["7z", "x", f"-o{dest}", archive_path, "-y"], timeout=timeout)
            logs.append(f"7z(iso) rc={cp.returncode}")
            return int(cp.returncode or 0)
        if self._has_binary("unzip"):
            cp = self._exec(["unzip", "-o", archive_path, "-d", dest], timeout=timeout)
            logs.append(f"unzip rc={cp.returncode}")
            return int(cp.returncode or 0)
        logs.append("no archive tool available")
        return 127

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
        metadata: Dict[str, Any] = {"launcher": "archive"}

        profile_cfg = getattr(profile, "config", {}) or {}
        timeout = int(profile_cfg.get("extract_timeout_s", 60))
        specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path
        ext = os.path.splitext(specimen_ref)[1].lower()
        dest = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}-extracted")

        exit_code = self._extract(specimen_ref, dest, ext, timeout, logs)

        # Surface extracted children for recursive dispatch.
        if os.path.isdir(dest):
            for root, _dirs, files in os.walk(dest):
                for name in files:
                    artifacts.append(os.path.join(root, name))
        metadata["extracted_count"] = len(artifacts)
        metadata["extract_dir"] = dest

        duration_ms = int((time.monotonic() - start) * 1000)
        return LauncherResult(
            exit_code=exit_code,
            duration_ms=duration_ms,
            pcap_path=None,
            memory_dump_path=None,
            ebpf_events=[],
            artifacts=artifacts,
            logs=logs,
            metadata=metadata,
        )


__all__ = ["ArchiveLauncher"]
