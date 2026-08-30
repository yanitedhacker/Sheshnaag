"""Windows libvirt/KVM provider for Sheshnaag V6 detonation."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from typing import Any

from app.core.time import utc_now
from app.lab.interfaces import HealthStatus, LabProvider, ProviderResult, RunState
from app.lab.libvirt_contract import LIBVIRT_URI, resolve_libvirt_domain

WINDOWS_IMAGE = os.environ.get("SHESHNAAG_WINDOWS_IMAGE", "sheshnaag-windows-golden")
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
        sandbox_profile = run_context.get("sandbox_profile") or {}
        profile_config = sandbox_profile.get("config") or {}
        domain = resolve_libvirt_domain(vm, profile_config)
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
                "domain": domain,
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
                "domain": domain,
            },
            "provider_readiness": self._readiness(probe=launch_mode != "execute"),
            "synthetic_sysmon": [
                {"EventID": 1, "Image": "C:\\sample.exe", "CommandLine": "sample.exe"},
            ],
        }

    def _readiness(self, *, probe: bool = True) -> dict[str, Any]:
        if self._virsh_available():
            if not probe:
                return {"status": "available", "virsh": True, "uri": LIBVIRT_URI}
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
        domain = str(plan["vm"]["domain"])
        launch_mode = plan.get("launch_mode", "simulated")
        self._domains[domain] = {
            "plan": plan,
            "state": RunState.READY if launch_mode != "execute" else RunState.BOOTING,
            "created_at": utc_now().isoformat(),
        }
        if launch_mode == "execute":
            if not self._virsh_available():
                return self._execution_error(
                    domain,
                    plan,
                    "virsh is required for execute-mode libvirt runs",
                )
            domain_info = self._virsh("dominfo", domain, timeout=15)
            if domain_info.returncode != 0:
                return self._execution_error(
                    domain,
                    plan,
                    domain_info.stderr or "libvirt domain check failed",
                )
            domain_state = self._virsh("domstate", domain, timeout=15)
            if domain_state.returncode != 0:
                return self._execution_error(
                    domain,
                    plan,
                    domain_state.stderr or "libvirt domain state check failed",
                )
            if "running" not in str(domain_state.stdout or "").strip().lower():
                started = self._virsh("start", domain, timeout=30)
                if started.returncode != 0:
                    return self._execution_error(
                        domain,
                        plan,
                        started.stderr or "libvirt domain start failed",
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

    def _virsh(self, action: str, domain: str, *, timeout: int):
        return subprocess.run(
            ["virsh", "-c", LIBVIRT_URI, action, domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _execution_error(
        self,
        domain: str,
        plan: dict[str, Any],
        error: str,
    ) -> ProviderResult:
        self._domains[domain]["state"] = RunState.ERRORED
        return ProviderResult(
            state=RunState.ERRORED,
            provider_run_ref=domain,
            plan=plan,
            transcript=f"libvirt domain {domain} failed to start",
            health=HealthStatus.ERRORED,
            error=str(error).strip() or "libvirt_execution_failed",
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
        state = entry["state"]
        if state == RunState.RUNNING and self._virsh_available():
            result = self._virsh("domstate", provider_run_ref, timeout=15)
            if result.returncode != 0:
                state = RunState.ERRORED
                entry["state"] = state
            elif "running" not in str(result.stdout or "").strip().lower():
                state = RunState.STOPPED
                entry["state"] = state
        return ProviderResult(
            state=state,
            provider_run_ref=provider_run_ref,
            plan=entry.get("plan", {}),
            health=(
                HealthStatus.READY
                if state in {RunState.READY, RunState.RUNNING}
                else HealthStatus.STOPPED
                if state == RunState.STOPPED
                else HealthStatus.ERRORED
            ),
        )

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        entry = self._domains.get(provider_run_ref)
        if entry is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                health=HealthStatus.ERRORED,
                error="domain_not_found",
            )
        if entry.get("plan", {}).get("launch_mode") == "execute":
            if not self._virsh_available():
                return self._execution_error(
                    provider_run_ref,
                    entry.get("plan", {}),
                    "virsh is required to stop the libvirt domain",
                )
            stopped = self._virsh("destroy", provider_run_ref, timeout=30)
            if stopped.returncode != 0:
                return self._execution_error(
                    provider_run_ref,
                    entry.get("plan", {}),
                    stopped.stderr or "libvirt domain stop failed",
                )
        entry["state"] = RunState.STOPPED
        return ProviderResult(
            state=RunState.STOPPED,
            provider_run_ref=provider_run_ref,
            health=HealthStatus.STOPPED,
        )

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        entry = self._domains.get(provider_run_ref)
        if entry is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                health=HealthStatus.ERRORED,
                error="domain_not_found",
            )
        if entry["state"] == RunState.RUNNING:
            stopped = self.stop(provider_run_ref=provider_run_ref)
            if stopped.state == RunState.ERRORED:
                return stopped
        self._domains.pop(provider_run_ref, None)
        state = RunState.DESTROYED
        return ProviderResult(
            state=state,
            provider_run_ref=provider_run_ref,
            health=HealthStatus.DESTROYED,
        )

    def revert_snapshot(self, *, provider_run_ref: str, snapshot_name: str = "baseline") -> ProviderResult:
        if not self._virsh_available():
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                health=HealthStatus.ERRORED,
                error="virsh is required to revert a libvirt snapshot",
            )
        result = subprocess.run(
            ["virsh", "-c", LIBVIRT_URI, "snapshot-revert", provider_run_ref, snapshot_name],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode != 0:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                health=HealthStatus.ERRORED,
                error=result.stderr or "libvirt snapshot revert failed",
            )
        return ProviderResult(
            state=RunState.READY,
            provider_run_ref=provider_run_ref,
            transcript=f"reverted {provider_run_ref} to {snapshot_name}",
            health=HealthStatus.READY,
        )
