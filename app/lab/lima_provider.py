"""Lima VM provider contract stub for Sheshnaag lab runs.

This module defines ``LimaProvider``, a **discoverable** placeholder that is **not
active** by default (``is_active = False``). It exists so future **secure-mode,
VM-backed** validation runs can plug into the same ``LabProvider`` /
``ProviderResult`` contract as container-based providers—without redesigning
orchestration, typing, or registry wiring when Lima integration lands.

A full implementation will coordinate ``limactl`` lifecycle, guest workspace
sync, attestation, and teardown policies. Each lifecycle stage below documents
**snapshot** and **revert** touchpoints (e.g. qcow2 checkpoints, last-known-good
rollback) that a production provider should expose or honor.
"""

from __future__ import annotations

from typing import Any, Dict
from uuid import uuid4

from app.lab.interfaces import HealthStatus, LabProvider, ProviderResult, RunState


class LimaProvider(LabProvider):
    """Contract stub for Lima-backed VMs; execution paths are not implemented."""

    provider_name = "lima"
    is_active = False

    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        vm = revision_content.get("vm") or {}
        cpu = int(vm.get("cpu") or revision_content.get("vm_cpu") or 2)
        memory_mb = int(vm.get("memory_mb") or revision_content.get("vm_memory_mb") or 4096)
        disk_gb = int(vm.get("disk_gb") or revision_content.get("vm_disk_gb") or 20)
        lima_yaml_template_path = str(
            vm.get("lima_yaml_template_path")
            or revision_content.get("lima_yaml_template_path")
            or "templates/lima/sheshnaag-default.yaml"
        )

        return {
            "provider": self.provider_name,
            "vm": {
                "cpu": cpu,
                "memory_mb": memory_mb,
                "disk_gb": disk_gb,
                "lima_yaml_template_path": lima_yaml_template_path,
            },
            "run_context": {
                "tenant_slug": run_context.get("tenant_slug"),
                "analyst_name": run_context.get("analyst_name"),
                "run_id": run_context.get("run_id"),
            },
        }

    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        provider_run_ref = f"lima-stub-{uuid4().hex}"
        return ProviderResult(
            state=RunState.BLOCKED,
            provider_run_ref=provider_run_ref,
            plan=plan,
            transcript="Lima provider is a contract stub; full VM execution is not yet implemented.",
            health=HealthStatus.UNKNOWN,
        )

    def create(self, *, plan: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.create is not implemented. A full provider must render Lima YAML from "
            "plan['vm'], allocate a Lima instance directory, persist provider_run_ref ↔ instance "
            "identity, and expose snapshot hooks after disk provisioning (e.g. baseline backing "
            "image or qcow2 snapshot before first boot) plus revert if allocation or template "
            "render fails mid-flight."
        )

    def boot(self, *, provider_run_ref: str) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.boot is not implemented. A full provider must run `limactl start` (or "
            "equivalent), wait for SSH/socket readiness, and add post-boot snapshot hooks "
            "(checkpoint after cloud-init or agent registration) with a revert path if boot "
            "stalls or the guest never becomes reachable."
        )

    def health(self, *, provider_run_ref: str) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.health is not implemented. A full provider must probe guest health "
            "(SSH, systemd, or in-guest agent), map results to HealthStatus, and optionally "
            "trigger revert-to-last-known-good snapshot behavior when probes fail repeatedly "
            "or indicate corruption."
        )

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.stop is not implemented. A full provider must issue graceful shutdown "
            "(`limactl stop` or guest `poweroff`), optionally take a pre-stop snapshot for "
            "forensics, and define revert semantics if stop leaves disks or Lima metadata in "
            "an inconsistent partial state."
        )

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.teardown is not implemented. A full provider must release VM runtime "
            "resources while honoring retain_workspace (retain vs delete instance disks and "
            "mounts), coordinate artifact export, and use snapshot/revert guards when partial "
            "teardown must be rolled back or retried safely."
        )

    def destroy(self, *, provider_run_ref: str) -> ProviderResult:
        raise NotImplementedError(
            "LimaProvider.destroy is not implemented. A full provider must remove the Lima "
            "instance and backing stores (`limactl delete` / disk cleanup), clear ref mappings "
            "in orchestration state, and document revert or compensating actions if destroy "
            "fails partway (e.g. orphaned volumes) for audit and retry."
        )
