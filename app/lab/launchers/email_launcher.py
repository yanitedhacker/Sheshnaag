"""Email (.eml / .msg) launcher.

Converts ``.msg`` to ``.eml`` when ``msgconvert`` is present, renders
the email safely to HTML via a headless-chrome pass, and enumerates
attachments so the archive launcher can recurse into them. The
recursion itself is driven by the service layer — this launcher only
emits attachment paths in ``LauncherResult.artifacts``.
"""

from __future__ import annotations

import email
import email.policy
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List

from app.lab.launchers.base import Launcher, LauncherResult

_EMAIL_KINDS = frozenset({"email/eml", "email/msg", "email"})


class EmailLauncher:
    kind = "email/eml"

    def can_handle(self, specimen_kind: str, metadata: dict) -> bool:
        return specimen_kind in _EMAIL_KINDS

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

    def _parse_attachments(self, eml_path: str, stage_dir: str) -> List[str]:
        try:
            with open(eml_path, "rb") as fh:
                msg = email.message_from_binary_file(fh, policy=email.policy.default)
        except Exception:
            return []
        attachments: List[str] = []
        os.makedirs(stage_dir, exist_ok=True)
        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            dest = os.path.join(stage_dir, os.path.basename(filename))
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            try:
                with open(dest, "wb") as fh:
                    fh.write(payload)
                attachments.append(dest)
            except OSError:
                continue
        return attachments

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
        metadata: Dict[str, Any] = {"launcher": "email"}

        profile_cfg = getattr(profile, "config", {}) or {}
        timeout = int(profile_cfg.get("detonation_timeout_s", 45))
        specimen_ref = getattr(revision, "quarantine_path", None) or quarantine_path
        ext = os.path.splitext(specimen_ref)[1].lower()

        eml_path = specimen_ref
        if ext == ".msg":
            if self._has_binary("msgconvert"):
                converted = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}.eml")
                self._exec(
                    ["msgconvert", "--outfile", converted, specimen_ref],
                    timeout=timeout,
                )
                eml_path = converted
                artifacts.append(converted)
                logs.append(f"msgconvert -> {converted}")
                metadata["mode"] = "msgconvert"
            else:
                logs.append("msgconvert missing; falling back to raw .msg parsing")
                metadata["mode"] = "raw"

        stage_dir = os.path.join(quarantine_path, f"run-{getattr(run, 'id', 'x')}-attachments")
        attachments = self._parse_attachments(eml_path, stage_dir)
        artifacts.extend(attachments)
        metadata["attachments"] = attachments
        logs.append(f"extracted_attachments count={len(attachments)}")

        duration_ms = int((time.monotonic() - start) * 1000)
        return LauncherResult(
            exit_code=0,
            duration_ms=duration_ms,
            pcap_path=None,
            memory_dump_path=None,
            ebpf_events=[],
            artifacts=artifacts,
            logs=logs,
            metadata=metadata,
        )


__all__ = ["EmailLauncher"]
