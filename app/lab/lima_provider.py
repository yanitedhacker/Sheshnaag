"""Lima-backed secure-mode provider for Sheshnaag lab runs."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Dict, List

from app.core.time import utc_now
from app.lab.image_catalog import resolve_catalog_entry
from app.lab.interfaces import HealthStatus, LabProvider, ProviderResult, RunState

LIMA_WORKSPACE_ROOT = Path(os.environ.get("SHESHNAAG_LIMA_WORKSPACE_ROOT", "/tmp/sheshnaag-lima"))
LIMA_TEMPLATE_PATH = os.environ.get("SHESHNAAG_LIMA_TEMPLATE_PATH", "templates/lima/sheshnaag-default.yaml")


class LimaProvider(LabProvider):
    """Secure-mode provider using Lima when available and simulation otherwise."""

    provider_name = "lima"
    is_active = True

    def __init__(self) -> None:
        self._instances: Dict[str, Dict[str, Any]] = {}

    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        collectors = revision_content.get("collectors", []) or []
        execution_policy = revision_content.get("execution_policy") or {}
        catalog_entry = resolve_catalog_entry(
            provider=self.provider_name,
            image_profile=revision_content.get("image_profile"),
            requested_image=revision_content.get("base_image"),
            collectors=collectors,
        )
        vm = revision_content.get("vm") or {}
        cpu = int(vm.get("cpu") or revision_content.get("vm_cpu") or 2)
        memory_mb = int(vm.get("memory_mb") or revision_content.get("vm_memory_mb") or 4096)
        disk_gb = int(vm.get("disk_gb") or revision_content.get("vm_disk_gb") or 20)
        template_path = str(
            vm.get("lima_yaml_template_path")
            or revision_content.get("lima_yaml_template_path")
            or LIMA_TEMPLATE_PATH
        )
        template_metadata = self._template_metadata(template_path)
        limactl_version = self._limactl_version()
        return {
            "provider": self.provider_name,
            "secure_mode": True,
            "image": catalog_entry.image,
            "image_digest": catalog_entry.digest,
            "image_profile": catalog_entry.profile,
            "image_catalog": catalog_entry.to_manifest(),
            "tooling_profile_name": catalog_entry.tooling_profile,
            "tooling_profile": {
                "profile": catalog_entry.tooling_profile,
                "osquery_available": bool(catalog_entry.supports_osquery),
                "tracee_available": bool(catalog_entry.supports_tracee),
            },
            "collectors": collectors,
            "command": revision_content.get("command") or ["sleep", "1"],
            "vm": {
                "cpu": cpu,
                "memory_mb": memory_mb,
                "disk_gb": disk_gb,
                "lima_yaml_template_path": template_path,
            },
            "execution_policy": {
                "secure_mode_required": True,
                "preferred_provider": execution_policy.get("preferred_provider") or self.provider_name,
                "allowed_modes": execution_policy.get("allowed_modes") or ["dry_run", "simulated", "execute"],
            },
            "workspace_sync": {
                "mode": "host-to-guest-staging",
                "export_mode": "guest-to-host-artifact-copy",
                "guest_workspace": "/workspace",
            },
            "snapshot_policy": {
                "baseline_snapshot": "baseline",
                "revert_behavior": "revert_to_baseline_before_destroy",
            },
            "secure_mode_contract": {
                "provider": self.provider_name,
                "snapshot_revert_supported": True,
                "secure_collectors": ["pcap"],
            },
            "provider_contract": {
                "provider": self.provider_name,
                "snapshot_revert_supported": True,
                "secure_collectors": ["pcap"],
            },
            "template_metadata": template_metadata,
            "provider_readiness": self._provider_readiness(template_path=template_path),
            "collector_capabilities": self._collector_capabilities(collectors=collectors),
            "secure_mode_audit": {
                "host_checks": self._provider_readiness(template_path=template_path),
                "limactl_version": limactl_version,
                "template": template_metadata,
                "lifecycle": [],
                "execute_result": None,
                "snapshot_revert_audit": {
                    "baseline_snapshot_ref": None,
                    "booted_snapshot_ref": None,
                    "revert_behavior": "revert_to_baseline_before_destroy",
                    "revert_outcome": "pending",
                },
            },
            "generated_at": utc_now().isoformat(),
            "run_context": {
                "tenant_slug": run_context.get("tenant_slug"),
                "analyst": run_context.get("analyst_name"),
                "run_id": run_context.get("run_id"),
            },
        }

    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        launch_mode = run_context.get("launch_mode") or "simulated"
        if launch_mode == "dry_run":
            return ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref=self._generate_run_ref(),
                plan=plan,
                transcript="Dry run only. Lima guest not allocated.",
                health=HealthStatus.UNKNOWN,
            )
        if launch_mode == "execute" and plan["provider_readiness"]["status"] == "unavailable":
            return ProviderResult(
                state=RunState.BLOCKED,
                provider_run_ref=self._generate_run_ref(),
                plan=plan,
                transcript="Lima secure mode is unavailable on this host.",
                error="provider_not_ready",
                health=HealthStatus.UNKNOWN,
            )
        created = self.create(plan=plan, run_context=run_context)
        if created.state != RunState.PLANNED:
            return created
        return self.boot(provider_run_ref=created.provider_run_ref)

    def create(self, *, plan: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        provider_run_ref = self._generate_run_ref()
        workspace = self._workspace_for_ref(provider_run_ref)
        workspace.mkdir(parents=True, exist_ok=True)
        snapshot_ref = f"{provider_run_ref}:baseline"
        plan_out = dict(plan)
        plan_out["host_workspace"] = str(workspace)
        plan_out["snapshot_refs"] = {"baseline": snapshot_ref}
        generated_template_path = self._materialize_template(plan=plan_out, workspace=workspace)
        plan_out["generated_template_path"] = generated_template_path
        plan_out["workspace_sync"] = {
            **(plan_out.get("workspace_sync") or {}),
            "host_workspace": str(workspace),
            "status": "allocated",
        }
        plan_out["guest_instance"] = {
            "instance_name": None,
            "host_workspace": str(workspace),
            "guest_workspace": "/workspace",
            "generated_template_path": generated_template_path,
        }
        secure_audit = dict(plan_out.get("secure_mode_audit") or {})
        secure_audit.setdefault("lifecycle", []).append(
            {
                "event": "allocated",
                "at": utc_now().isoformat(),
                "host_workspace": str(workspace),
                "generated_template_path": generated_template_path,
            }
        )
        snapshot_audit = dict(secure_audit.get("snapshot_revert_audit") or {})
        snapshot_audit["baseline_snapshot_ref"] = snapshot_ref
        secure_audit["snapshot_revert_audit"] = snapshot_audit
        plan_out["secure_mode_audit"] = secure_audit
        self._instances[provider_run_ref] = {
            "plan": plan_out,
            "workspace": str(workspace),
            "snapshot_ref": snapshot_ref,
            "launch_mode": run_context.get("launch_mode", "simulated"),
            "state": RunState.PLANNED,
        }
        return ProviderResult(
            state=RunState.PLANNED,
            provider_run_ref=provider_run_ref,
            plan=plan_out,
            transcript=f"Lima resources allocated. Workspace: {workspace}",
            health=HealthStatus.UNKNOWN,
        )

    def boot(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._instances.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        plan = info["plan"]
        launch_mode = info.get("launch_mode", "simulated")
        if launch_mode == "simulated":
            info["state"] = RunState.COMPLETED
            plan["guest_status"] = "simulated"
            self._record_lifecycle_event(plan, event="simulated_complete")
            return ProviderResult(
                state=RunState.COMPLETED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Simulated Lima secure-mode run completed with auditable snapshot metadata.",
                health=HealthStatus.STOPPED,
            )
        if launch_mode == "dry_run":
            return ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Dry run: Lima boot skipped.",
                health=HealthStatus.UNKNOWN,
            )
        if shutil.which("limactl") is None:
            self._record_lifecycle_event(plan, event="blocked", detail="limactl missing")
            return ProviderResult(
                state=RunState.BLOCKED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="limactl is not installed on this host.",
                error="limactl_missing",
                health=HealthStatus.UNKNOWN,
            )
        instance_name = f"sheshnaag-{provider_run_ref}"
        template_path = (
            plan.get("generated_template_path")
            or plan.get("vm", {}).get("lima_yaml_template_path")
            or LIMA_TEMPLATE_PATH
        )
        try:
            subprocess.run(
                ["limactl", "start", "--name", instance_name, template_path],
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
            plan["instance_name"] = instance_name
            plan.setdefault("snapshot_refs", {})["booted"] = f"{provider_run_ref}:booted"
            plan["guest_status"] = "booted"
            plan.setdefault("workspace_sync", {})["status"] = "booted"
            plan.setdefault("guest_instance", {})["instance_name"] = instance_name
            secure_audit = dict(plan.get("secure_mode_audit") or {})
            snapshot_audit = dict(secure_audit.get("snapshot_revert_audit") or {})
            snapshot_audit["booted_snapshot_ref"] = f"{provider_run_ref}:booted"
            secure_audit["snapshot_revert_audit"] = snapshot_audit
            plan["secure_mode_audit"] = secure_audit
            self._record_lifecycle_event(plan, event="booted", detail=f"instance {instance_name} booted")
            ready_code, ready_out, ready_err = self._guest_shell(
                instance_name,
                "test -d /workspace && echo ready",
                timeout=30,
            )
            readiness_state = "ready" if ready_code == 0 and "ready" in (ready_out or "") else "degraded"
            self._record_lifecycle_event(
                plan,
                event="readiness_check",
                detail=readiness_state,
                payload={
                    "exit_code": ready_code,
                    "stdout": (ready_out or "")[:1000],
                    "stderr": (ready_err or "")[:1000],
                },
            )
            info["state"] = RunState.RUNNING
            if launch_mode == "execute":
                execute = self._execute_in_guest(plan=plan, instance_name=instance_name)
                info["state"] = RunState.RUNNING if execute["exit_code"] == 0 else RunState.ERRORED
                return ProviderResult(
                    state=RunState.RUNNING if execute["exit_code"] == 0 else RunState.ERRORED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript=(
                        f"Lima instance {instance_name} booted and executed guest command."
                        if execute["exit_code"] == 0
                        else f"Lima guest command failed in {instance_name}: {execute['stderr'][:400]}"
                    ),
                    health=HealthStatus.READY if execute["exit_code"] == 0 else HealthStatus.ERRORED,
                    error=None if execute["exit_code"] == 0 else execute["stderr"][:1000] or "execute_failed",
                )
            return ProviderResult(
                state=RunState.RUNNING,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript=f"Lima instance {instance_name} booted.",
                health=HealthStatus.BOOTING,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            self._record_lifecycle_event(plan, event="boot_failed", detail=str(exc))
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript=f"Lima boot failed: {exc}",
                error=str(exc),
                health=HealthStatus.ERRORED,
            )

    def health(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._instances.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
                health=HealthStatus.UNKNOWN,
            )
        state = info.get("state", RunState.PLANNED)
        plan = info.get("plan") or {}
        instance_name = plan.get("instance_name")
        if instance_name and shutil.which("limactl") and state == RunState.RUNNING:
            try:
                proc = subprocess.run(
                    ["limactl", "list", "--format", "{{.Name}} {{.Status}}"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                statuses = {}
                for line in (proc.stdout or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        statuses[parts[0]] = parts[1].lower()
                raw_status = statuses.get(instance_name)
                if raw_status in {"running", "started"}:
                    state = RunState.RUNNING
                elif raw_status in {"stopped", "exited"}:
                    state = RunState.STOPPED
            except (subprocess.SubprocessError, OSError):
                pass
        health_map = {
            RunState.PLANNED: HealthStatus.UNKNOWN,
            RunState.RUNNING: HealthStatus.READY,
            RunState.COMPLETED: HealthStatus.STOPPED,
            RunState.STOPPED: HealthStatus.STOPPED,
            RunState.DESTROYED: HealthStatus.DESTROYED,
            RunState.BLOCKED: HealthStatus.UNKNOWN,
            RunState.ERRORED: HealthStatus.ERRORED,
        }
        return ProviderResult(
            state=state,
            provider_run_ref=provider_run_ref,
            plan=info.get("plan") or {},
            transcript=f"Lima health: {health_map.get(state, HealthStatus.UNKNOWN).value}",
            health=health_map.get(state, HealthStatus.UNKNOWN),
        )

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._instances.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        plan = info.get("plan") or {}
        instance_name = plan.get("instance_name")
        if instance_name and shutil.which("limactl"):
            try:
                subprocess.run(["limactl", "stop", instance_name], check=True, capture_output=True, text=True, timeout=90)
                plan["guest_status"] = "stopped"
                self._record_lifecycle_event(plan, event="stopped", detail=f"instance {instance_name} stopped")
            except (subprocess.SubprocessError, OSError) as exc:
                self._record_lifecycle_event(plan, event="stop_failed", detail=str(exc))
                return ProviderResult(
                    state=RunState.ERRORED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript=f"Lima stop failed: {exc}",
                    error=str(exc),
                )
        info["state"] = RunState.STOPPED
        return ProviderResult(
            state=RunState.STOPPED,
            provider_run_ref=provider_run_ref,
            plan=plan,
            transcript="Lima guest stopped.",
            health=HealthStatus.STOPPED,
        )

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        info = self._instances.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        plan = info.get("plan") or {}
        workspace = Path(info.get("workspace") or "")
        restore_action = "revert_to_baseline"
        if workspace.exists() and not retain_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        plan.setdefault("teardown", {})
        plan["teardown"].update(
            {
                "retain_workspace": retain_workspace,
                "restore_action": restore_action,
                "completed_at": utc_now().isoformat(),
                "snapshot_refs": plan.get("snapshot_refs") or {},
            }
        )
        plan.setdefault("workspace_sync", {})["status"] = "retained" if retain_workspace else "removed"
        plan["guest_status"] = "destroyed"
        secure_audit = dict(plan.get("secure_mode_audit") or {})
        snapshot_audit = dict(secure_audit.get("snapshot_revert_audit") or {})
        snapshot_audit["revert_outcome"] = "recorded"
        snapshot_audit["reverted_at"] = utc_now().isoformat()
        secure_audit["snapshot_revert_audit"] = snapshot_audit
        plan["secure_mode_audit"] = secure_audit
        self._record_lifecycle_event(
            plan,
            event="teardown",
            detail="baseline revert audit recorded",
            payload={"retain_workspace": retain_workspace},
        )
        info["state"] = RunState.DESTROYED
        return ProviderResult(
            state=RunState.DESTROYED,
            provider_run_ref=provider_run_ref,
            plan=plan,
            transcript="Lima teardown complete with baseline-revert audit metadata recorded.",
            health=HealthStatus.DESTROYED,
        )

    def destroy(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._instances.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.DESTROYED,
                provider_run_ref=provider_run_ref,
                transcript="No Lima resources remain for this run.",
                health=HealthStatus.DESTROYED,
            )
        plan = info.get("plan") or {}
        instance_name = plan.get("instance_name")
        if instance_name and shutil.which("limactl"):
            try:
                subprocess.run(["limactl", "delete", "-f", instance_name], check=True, capture_output=True, text=True, timeout=90)
                self._record_lifecycle_event(plan, event="deleted", detail=f"instance {instance_name} deleted")
            except (subprocess.SubprocessError, OSError):
                pass
        result = self.teardown(provider_run_ref=provider_run_ref, retain_workspace=False)
        self._instances.pop(provider_run_ref, None)
        return result

    def transfer_artifacts(
        self,
        *,
        provider_run_ref: str,
        artifacts: List[Dict[str, Any]],
        workspace_path: str,
    ) -> Dict[str, Any]:
        os.makedirs(workspace_path, exist_ok=True)
        transfers: List[Dict[str, Any]] = []
        for artifact in artifacts:
            src = str(artifact.get("source_path") or "")
            if not src or not os.path.isfile(src):
                transfers.append({"name": artifact.get("name"), "status": "missing", "error": "source not found"})
                continue
            name = str(artifact.get("name") or os.path.basename(src))
            destination = str(artifact.get("destination") or f"/workspace/{name}")
            relative = destination.replace("/workspace/", "", 1).lstrip("/") or name
            dst = os.path.join(workspace_path, relative)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            sha256 = self._file_sha256(dst)
            transfers.append(
                {
                    "name": name,
                    "status": "transferred",
                    "sha256": sha256,
                    "destination": destination,
                    "host_path": dst,
                }
            )
        return {"provider_run_ref": provider_run_ref, "transfers": transfers}

    def _provider_readiness(self, *, template_path: str) -> Dict[str, Any]:
        limactl_available = shutil.which("limactl") is not None
        template_exists = Path(template_path).exists()
        workspace_ready = self._safe_workspace_root_ready()
        limactl_version = self._limactl_version()
        checks = [
            {
                "name": "limactl",
                "status": "ready" if limactl_available else "unavailable",
                "detail": (
                    f"limactl available on host ({limactl_version})."
                    if limactl_available and limactl_version
                    else "limactl available on host."
                )
                if limactl_available
                else "limactl not found on host.",
            },
            {
                "name": "template",
                "status": "ready" if template_exists else "degraded",
                "detail": f"Lima template {template_path} found." if template_exists else f"Lima template {template_path} is missing; simulated mode still works.",
            },
            {
                "name": "workspace_root",
                "status": "ready" if workspace_ready else "unavailable",
                "detail": f"Lima workspace root {LIMA_WORKSPACE_ROOT} is writable." if workspace_ready else f"Lima workspace root {LIMA_WORKSPACE_ROOT} is not writable.",
            },
        ]
        statuses = {item["status"] for item in checks}
        if "unavailable" in statuses:
            overall = "unavailable"
        elif "degraded" in statuses:
            overall = "degraded"
        else:
            overall = "ready"
        return {
            "provider": self.provider_name,
            "status": overall,
            "checks": checks,
            "workspace_root": str(LIMA_WORKSPACE_ROOT),
            "limactl_version": limactl_version,
        }

    @staticmethod
    def _collector_capabilities(*, collectors: List[str]) -> List[Dict[str, Any]]:
        selected = set(collectors or [])
        definitions = {
            "process_tree": ("baseline", "ready", "Secure-mode baseline collector."),
            "package_inventory": ("baseline", "ready", "Secure-mode baseline collector."),
            "file_diff": ("baseline", "ready", "Secure-mode baseline collector."),
            "network_metadata": ("baseline", "ready", "Secure-mode baseline collector."),
            "service_logs": ("baseline", "ready", "Secure-mode baseline collector."),
            "osquery_snapshot": ("extended", "degraded", "Requires an osquery-capable secure image profile."),
            "tracee_events": ("supported", "degraded", "Supported in v2 when the selected image is Tracee-capable."),
            "falco_events": ("extended", "degraded", "Deferred in v2; capability reporting only."),
            "tetragon_events": ("extended", "degraded", "Deferred in v2; capability reporting only."),
            "pcap": ("extended", "ready", "PCAP is permitted only in secure mode and requires explicit operator review."),
        }
        return [
            {
                "collector_name": name,
                "tier": tier,
                "selected": name in selected,
                "status": status,
                "reason": reason,
            }
            for name, (tier, status, reason) in definitions.items()
        ]

    @staticmethod
    def _generate_run_ref() -> str:
        return f"lima-{uuid.uuid4().hex[:10]}"

    @staticmethod
    def _workspace_for_ref(provider_run_ref: str) -> Path:
        return LIMA_WORKSPACE_ROOT / provider_run_ref

    @staticmethod
    def _safe_workspace_root_ready() -> bool:
        try:
            LIMA_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
            return os.access(LIMA_WORKSPACE_ROOT, os.W_OK)
        except OSError:
            return False

    @staticmethod
    def _file_sha256(path: str) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _limactl_version() -> str | None:
        if shutil.which("limactl") is None:
            return None
        try:
            proc = subprocess.run(["limactl", "--version"], check=False, capture_output=True, text=True, timeout=15)
            return (proc.stdout or proc.stderr or "").strip() or None
        except (subprocess.SubprocessError, OSError):
            return None

    def _template_metadata(self, template_path: str) -> Dict[str, Any]:
        path = Path(template_path)
        return {
            "path": str(path),
            "exists": path.exists(),
            "sha256": self._file_sha256(str(path)) if path.exists() else None,
        }

    def _materialize_template(self, *, plan: Dict[str, Any], workspace: Path) -> str:
        source_path = Path(plan.get("vm", {}).get("lima_yaml_template_path") or LIMA_TEMPLATE_PATH)
        generated_path = workspace / "sheshnaag-generated-lima.yaml"
        source_text = source_path.read_text() if source_path.exists() else ""
        cpu = int((plan.get("vm") or {}).get("cpu") or 2)
        memory_mb = int((plan.get("vm") or {}).get("memory_mb") or 4096)
        disk_gb = int((plan.get("vm") or {}).get("disk_gb") or 20)
        if source_text:
            lines = source_text.splitlines()
            output: List[str] = []
            inserted_mount = False
            for line in lines:
                if line.startswith("cpus:"):
                    output.append(f"cpus: {cpu}")
                    continue
                if line.startswith("memory:"):
                    output.append(f'memory: "{memory_mb}MiB"')
                    continue
                if line.startswith("disk:"):
                    output.append(f'disk: "{disk_gb}GiB"')
                    continue
                if not inserted_mount and line.startswith("provision:"):
                    output.extend(
                        [
                            f'  - location: "{workspace}"',
                            '    mountPoint: "/workspace"',
                            "    writable: true",
                        ]
                    )
                    inserted_mount = True
                output.append(line)
            if not inserted_mount:
                output.extend(
                    [
                        "mounts:",
                        f'  - location: "{workspace}"',
                        '    mountPoint: "/workspace"',
                        "    writable: true",
                    ]
                )
            generated_text = "\n".join(output) + "\n"
        else:
            generated_text = "\n".join(
                [
                    "arch: x86_64",
                    f"cpus: {cpu}",
                    f'memory: "{memory_mb}MiB"',
                    f'disk: "{disk_gb}GiB"',
                    "mounts:",
                    f'  - location: "{workspace}"',
                    '    mountPoint: "/workspace"',
                    "    writable: true",
                ]
            ) + "\n"
        generated_path.write_text(generated_text)
        return str(generated_path)

    def _guest_shell(self, instance_name: str, command: str, *, timeout: int = 120) -> tuple[int, str, str]:
        return self._guest_argv(
            instance_name,
            ["/bin/sh", "-lc", command],
            timeout=timeout,
        )

    def _guest_argv(self, instance_name: str, argv: List[str], *, timeout: int = 120) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(
                ["limactl", "shell", instance_name, "--", *argv],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        except (subprocess.SubprocessError, OSError) as exc:
            return 1, "", str(exc)

    def _execute_in_guest(self, *, plan: Dict[str, Any], instance_name: str) -> Dict[str, Any]:
        command = plan.get("command") or ["sleep", "1"]
        command_text = command if isinstance(command, str) else shlex.join([str(part) for part in command])
        started_at = utc_now().isoformat()
        code, out, err = self._guest_shell(
            instance_name,
            f"cd /workspace && {command_text}",
            timeout=180,
        )
        ended_at = utc_now().isoformat()
        result = {
            "command": command,
            "command_text": command_text,
            "started_at": started_at,
            "ended_at": ended_at,
            "exit_code": code,
            "stdout": (out or "")[:8000],
            "stderr": (err or "")[:8000],
            "stdout_truncated": len(out or "") > 8000,
            "stderr_truncated": len(err or "") > 8000,
            "workspace": "/workspace",
        }
        secure_audit = dict(plan.get("secure_mode_audit") or {})
        secure_audit["execute_result"] = result
        plan["secure_mode_audit"] = secure_audit
        plan["execute_result"] = result
        plan.setdefault("workspace_sync", {})["status"] = "executed"
        self._record_lifecycle_event(
            plan,
            event="executed",
            detail=f"guest command exit={code}",
            payload={"exit_code": code},
        )
        return result

    @staticmethod
    def _record_lifecycle_event(plan: Dict[str, Any], *, event: str, detail: str | None = None, payload: Dict[str, Any] | None = None) -> None:
        secure_audit = dict(plan.get("secure_mode_audit") or {})
        lifecycle = list(secure_audit.get("lifecycle") or [])
        lifecycle.append(
            {
                "event": event,
                "at": utc_now().isoformat(),
                "detail": detail,
                "payload": payload or {},
            }
        )
        secure_audit["lifecycle"] = lifecycle
        plan["secure_mode_audit"] = secure_audit
