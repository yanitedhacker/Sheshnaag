"""Windows libvirt/KVM provider for Sheshnaag V6 detonation."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import uuid
from typing import Any

from app.core.time import utc_now
from app.lab.interfaces import HealthStatus, LabProvider, ProviderResult, RunState

WINDOWS_IMAGE = os.environ.get("SHESHNAAG_WINDOWS_IMAGE", "sheshnaag-windows-golden")
LIBVIRT_URI = os.environ.get("SHESHNAAG_LIBVIRT_URI", "qemu:///system")


class LibvirtWindowsProvider(LabProvider):
    """KVM/libvirt Windows guest provider with snapshot/revert support."""

    provider_name = "libvirt"
    is_active = True

    WINDOWS_COLLECTORS = ["sysmon_events", "etw_events", "process_tree", "file_diff"]

    def __init__(self) -> None:
        self._domains: dict[str, dict[str, Any]] = {}

    def _virsh_available(self) -> bool:
        return shutil.which("virsh") is not None

    def build_plan(
        self, *, revision_content: dict[str, Any], run_context: dict[str, Any]
    ) -> dict[str, Any]:
        launch_mode = (run_context.get("launch_mode") or "simulated").lower()
        collectors = list(revision_content.get("collectors") or self.WINDOWS_COLLECTORS)
        vm = revision_content.get("vm") or {}
        image = str(vm.get("image") or revision_content.get("base_image") or WINDOWS_IMAGE)
        return {
            "provider": self.provider_name,
            "secure_mode": True,
            "launch_mode": launch_mode,
            "image": image,
            "image_digest": hashlib.sha256(image.encode()).hexdigest(),
            "collectors": collectors,
            "vm": {
                "cpu": int(vm.get("cpu") or 4),
                "memory_mb": int(vm.get("memory_mb") or 8192),
                "disk_gb": int(vm.get("disk_gb") or 60),
                "os_family": "windows",
            },
            "telemetry": {"sysmon": True, "etw": True, "volatility_profile": "Win10x64"},
            "snapshot_policy": {
                "baseline_snapshot": "baseline",
                "revert_behavior": "domain_snapshot_revert",
            },
            "provider_contract": {
                "provider": self.provider_name,
                "snapshot_revert_supported": True,
                "secure_collectors": collectors,
            },
            "provider_readiness": self._readiness(),
            "synthetic_sysmon": [
                {"EventID": 1, "Image": "C:\\sample.exe", "CommandLine": "sample.exe"},
            ],
        }

    def _readiness(self) -> dict[str, Any]:
        if self._virsh_available():
            try:
                out = subprocess.run(
                    ["virsh", "-c", LIBVIRT_URI, "list", "--all"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                ok = out.returncode == 0
                return {"status": "ready" if ok else "degraded", "virsh": ok, "uri": LIBVIRT_URI}
            except (OSError, subprocess.TimeoutExpired):
                pass
        return {
            "status": "simulated",
            "virsh": False,
            "note": "virsh unavailable — simulated Windows detonation",
        }

    def launch(
        self, *, revision_content: dict[str, Any], run_context: dict[str, Any]
    ) -> ProviderResult:
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        domain = f"sheshnaag-{uuid.uuid4().hex[:8]}"
        launch_mode = plan.get("launch_mode", "simulated")
        self._domains[domain] = {
            "plan": plan,
            "state": RunState.READY if launch_mode != "execute" else RunState.BOOTING,
            "created_at": utc_now().isoformat(),
        }
        if launch_mode == "execute" and self._virsh_available():
            subprocess.run(
                ["virsh", "-c", LIBVIRT_URI, "snapshot-create-as", domain, "baseline"],
                capture_output=True,
                timeout=30,
                check=False,
            )
            self._domains[domain]["state"] = RunState.RUNNING
        transcript = f"libvirt domain {domain} planned ({launch_mode}) image={plan['image']}"
        return ProviderResult(
            state=self._domains[domain]["state"],
            provider_run_ref=domain,
            plan=plan,
            transcript=transcript,
            health=HealthStatus.READY,
        )

    def health(self, *, provider_run_ref: str) -> ProviderResult:
        entry = self._domains.get(provider_run_ref)
        if entry is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                error="domain_not_found",
                health=HealthStatus.ERRORED,
            )
        return ProviderResult(
            state=entry["state"],
            provider_run_ref=provider_run_ref,
            plan=entry.get("plan", {}),
            health=HealthStatus.READY,
        )

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        entry = self._domains.get(provider_run_ref)
        if entry:
            entry["state"] = RunState.STOPPED
        if self._virsh_available():
            subprocess.run(
                ["virsh", "-c", LIBVIRT_URI, "destroy", provider_run_ref],
                capture_output=True,
                timeout=30,
                check=False,
            )
        return ProviderResult(
            state=RunState.STOPPED,
            provider_run_ref=provider_run_ref,
            health=HealthStatus.STOPPED,
        )

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        entry = self._domains.pop(provider_run_ref, None)
        if self._virsh_available() and not retain_workspace:
            subprocess.run(
                ["virsh", "-c", LIBVIRT_URI, "undefine", provider_run_ref, "--remove-all-storage"],
                capture_output=True,
                timeout=60,
                check=False,
            )
        state = RunState.DESTROYED if entry else RunState.ERRORED
        return ProviderResult(
            state=state,
            provider_run_ref=provider_run_ref,
            health=HealthStatus.DESTROYED if entry else HealthStatus.ERRORED,
        )

    def revert_snapshot(self, *, provider_run_ref: str, snapshot_name: str = "baseline") -> ProviderResult:
        if self._virsh_available():
            subprocess.run(
                ["virsh", "-c", LIBVIRT_URI, "snapshot-revert", provider_run_ref, snapshot_name],
                capture_output=True,
                timeout=60,
                check=False,
            )
        return ProviderResult(
            state=RunState.READY,
            provider_run_ref=provider_run_ref,
            transcript=f"reverted {provider_run_ref} to {snapshot_name}",
            health=HealthStatus.READY,
        )
