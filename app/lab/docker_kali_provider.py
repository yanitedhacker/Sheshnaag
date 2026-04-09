"""Constrained Kali-on-Docker provider for Sheshnaag."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import uuid
from typing import Any, Dict, List, Optional

from app.core.time import utc_now
from app.lab.image_catalog import (
    DEFAULT_BASELINE_IMAGE,
    DEFAULT_OSQUERY_IMAGE,
    DEFAULT_TRACEE_IMAGE,
    find_image_by_name,
    resolve_catalog_entry,
)
from app.lab.interfaces import (
    HealthStatus,
    LabProvider,
    ProviderResult,
    RunState,
    validate_transition,
)

logger = logging.getLogger(__name__)

DEFAULT_KALI_IMAGE = DEFAULT_BASELINE_IMAGE
DEFAULT_SECURITY_OPTS = [
    "no-new-privileges:true",
    "apparmor=sheshnaag-default",
    "seccomp=default",
]
DEFAULT_CAP_DROP = ["ALL"]

WORKSPACE_ROOT = os.environ.get("SHESHNAAG_WORKSPACE_ROOT", "/tmp/sheshnaag")
LAUNCH_TIMEOUT_SECONDS = int(os.environ.get("SHESHNAAG_LAUNCH_TIMEOUT", "120"))

ALLOWED_NETWORK_MODES = ("none", "bridge")
BASELINE_EXECUTE_COLLECTORS = [
    "process_tree",
    "package_inventory",
    "file_diff",
    "network_metadata",
    "service_logs",
]
EXTENDED_EXECUTE_COLLECTORS = [
    "osquery_snapshot",
    "tracee_events",
    "falco_events",
    "tetragon_events",
    "pcap",
]


class DockerKaliProvider(LabProvider):
    """Prepare constrained Docker plans for Kali-based validation."""

    provider_name = "docker_kali"

    def __init__(self) -> None:
        self._active_containers: Dict[str, Dict[str, Any]] = {}

    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        allowlisted_hosts = revision_content.get("network_policy", {}).get("allow_egress_hosts", []) or []
        collectors = revision_content.get("collectors", []) or []
        execution_policy = revision_content.get("execution_policy") or {}
        catalog_entry = resolve_catalog_entry(
            provider=self.provider_name,
            image_profile=revision_content.get("image_profile"),
            requested_image=revision_content.get("base_image"),
            collectors=collectors,
        )
        image = catalog_entry.image
        image_digest = catalog_entry.digest
        tooling_profile = self._tooling_profile_for_image(image)

        requested_network = revision_content.get("network_policy", {}).get("mode", None)
        if requested_network and requested_network not in ALLOWED_NETWORK_MODES:
            requested_network = "none"
        network_mode = requested_network or ("none" if not allowlisted_hosts else "bridge")

        plan = {
            "provider": self.provider_name,
            "image": image,
            "image_digest": image_digest,
            "image_profile": catalog_entry.profile,
            "image_catalog": catalog_entry.to_manifest(),
            "command": revision_content.get("command") or ["sleep", "1"],
            "network_mode": network_mode,
            "allow_egress_hosts": allowlisted_hosts,
            "mounts": revision_content.get("mounts", []) or [],
            "read_only_rootfs": True,
            "tmpfs_mounts": ["/tmp", "/run", "/var/tmp"],
            "security_options": DEFAULT_SECURITY_OPTS,
            "cap_drop": DEFAULT_CAP_DROP,
            "cap_add": revision_content.get("cap_add", []) or [],
            "user": revision_content.get("user") or "root",
            "workdir": revision_content.get("workdir") or "/workspace",
            "workspace_mount_target": revision_content.get("workdir") or "/workspace",
            "collectors": collectors,
            "teardown_policy": revision_content.get("teardown_policy") or {
                "mode": "destroy_immediately",
                "ephemeral_workspace": True,
                "retain_export_only": True,
            },
            "workspace_retention": revision_content.get("workspace_retention") or "destroy_immediately",
            "acknowledgement_required": bool(
                revision_content.get("requires_acknowledgement") or revision_content.get("risk_level") in {"sensitive", "high"}
            ),
            "generated_at": utc_now().isoformat(),
            "tooling_profile_name": tooling_profile["profile"],
            "tooling_profile": tooling_profile,
            "execution_policy": {
                "secure_mode_required": bool(execution_policy.get("secure_mode_required")),
                "preferred_provider": execution_policy.get("preferred_provider") or self.provider_name,
                "allowed_modes": execution_policy.get("allowed_modes") or ["dry_run", "simulated", "execute"],
            },
            "run_context": {
                "tenant_slug": run_context.get("tenant_slug"),
                "analyst": run_context.get("analyst_name"),
                "run_id": run_context.get("run_id"),
            },
        }
        plan["docker_args"] = self._docker_args_for_plan(plan)
        plan["effective_network_policy"] = {
            "mode": network_mode,
            "allow_egress_hosts": allowlisted_hosts,
            "enforcement_note": (
                "Docker network mode=none provides full isolation. "
                "Bridge mode with host allowlists requires external firewall rules; "
                "Docker alone cannot enforce per-host egress filtering."
            ) if network_mode == "bridge" else "Full network isolation via Docker network=none.",
        }
        plan["provider_safety"] = {
            "read_only_rootfs": True,
            "default_cap_drop": list(DEFAULT_CAP_DROP),
            "security_options": list(DEFAULT_SECURITY_OPTS),
            "writable_mounts_require_policy": True,
            "pcap_policy": "secure_mode_only",
            "network_enforcement_limits": (
                "Bridge mode cannot enforce per-host egress allowlists without external firewall controls."
            ),
        }
        plan["provider_readiness"] = self._provider_readiness(
            image=image,
            network_mode=network_mode,
            collectors=collectors,
        )
        plan["collector_capabilities"] = self._collector_capabilities(collectors=collectors, image=image)
        plan["collector_policy"] = {
            "baseline_execute_defaults": list(BASELINE_EXECUTE_COLLECTORS),
            "extended_execute_collectors": list(EXTENDED_EXECUTE_COLLECTORS),
            "synthetic_modes": ["dry_run", "simulated"],
            "supported_advanced_collector": "tracee_events",
            "deferred_collectors": ["falco_events", "tetragon_events"],
            "secure_mode_only": ["pcap"],
        }
        # Optional evidence hints (WS6): copied into manifest so collectors can diff against baselines.
        for opt in ("file_manifest_baseline", "package_baseline", "log_sources"):
            if opt in revision_content:
                plan[opt] = revision_content[opt]
        return plan

    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        launch_mode = run_context.get("launch_mode") or "simulated"
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        provider_run_ref = self._generate_run_ref()
        workspace = self._workspace_for_ref(provider_run_ref)

        if launch_mode == "dry_run":
            plan_out = dict(plan)
            plan_out["host_workspace"] = workspace
            plan_out["docker_args"] = self._docker_args_for_plan(plan_out, host_workspace=workspace)
            return ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref=provider_run_ref,
                plan=plan_out,
                transcript="Dry run only. No container started.",
                health=HealthStatus.UNKNOWN,
            )

        if launch_mode == "execute":
            readiness = plan.get("provider_readiness") or {}
            if readiness.get("status") == "unavailable":
                return ProviderResult(
                    state=RunState.BLOCKED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript="Provider readiness check failed for execute mode.",
                    error="provider_not_ready",
                )
            try:
                subprocess.run(["docker", "version"], check=True, capture_output=True, text=True)
            except subprocess.SubprocessError as exc:
                return ProviderResult(
                    state=RunState.BLOCKED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript=f"Docker validation failed: {exc}",
                    error=str(exc),
                )

            os.makedirs(workspace, exist_ok=True)
            container_name = self._container_name(provider_run_ref)
            plan_out = dict(plan)
            plan_out["host_workspace"] = workspace
            plan_out["docker_args"] = self._docker_args_for_plan(plan_out, host_workspace=workspace)
            docker_args = list(plan_out["docker_args"])
            docker_args.insert(2, "--name")
            docker_args.insert(3, container_name)
            docker_args[docker_args.index("--rm")] = "--detach"

            for mount_spec in plan.get("mounts", []):
                src = mount_spec.get("source", "")
                dst = mount_spec.get("target", "")
                ro = mount_spec.get("read_only", True)
                if src and dst:
                    opt = f"{src}:{dst}:ro" if ro else f"{src}:{dst}"
                    docker_args.insert(-len(plan["command"]) - 1, "-v")
                    docker_args.insert(-len(plan["command"]) - 1, opt)

            try:
                result = subprocess.run(
                    docker_args,
                    capture_output=True,
                    text=True,
                    timeout=LAUNCH_TIMEOUT_SECONDS,
                )
                if result.returncode != 0:
                    stderr = result.stderr.strip()
                    return ProviderResult(
                        state=RunState.ERRORED,
                        provider_run_ref=provider_run_ref,
                        plan=plan_out,
                        transcript=f"Container launch failed: {stderr}",
                        error=stderr,
                    )

                container_id = result.stdout.strip()[:12]
                self._active_containers[provider_run_ref] = {
                    "container_id": container_id,
                    "container_name": container_name,
                    "workspace": workspace,
                    "plan": plan_out,
                    "state": RunState.RUNNING,
                }

                return ProviderResult(
                    state=RunState.RUNNING,
                    provider_run_ref=provider_run_ref,
                    plan=plan_out,
                    transcript=f"Container {container_name} launched ({container_id}).",
                    container_id=container_id,
                    health=HealthStatus.BOOTING,
                )
            except subprocess.TimeoutExpired:
                return ProviderResult(
                    state=RunState.ERRORED,
                    provider_run_ref=provider_run_ref,
                    plan=plan_out,
                    transcript=f"Container launch timed out after {LAUNCH_TIMEOUT_SECONDS}s.",
                    error="launch_timeout",
                    retry_after_seconds=30,
                )

        return ProviderResult(
            state=RunState.COMPLETED,
            provider_run_ref=provider_run_ref,
            plan=plan,
            transcript="Simulated constrained Kali run completed with synthetic evidence export.",
            health=HealthStatus.STOPPED,
        )

    def create(self, *, plan: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        provider_run_ref = self._generate_run_ref()
        workspace = self._workspace_for_ref(provider_run_ref)
        os.makedirs(workspace, exist_ok=True)
        plan_out = dict(plan)
        plan_out["host_workspace"] = workspace
        plan_out["docker_args"] = self._docker_args_for_plan(plan_out, host_workspace=workspace)
        self._active_containers[provider_run_ref] = {
            "container_id": None,
            "container_name": self._container_name(provider_run_ref),
            "workspace": workspace,
            "plan": plan_out,
            "state": RunState.PLANNED,
            "launch_mode": run_context.get("launch_mode", "simulated"),
        }
        return ProviderResult(
            state=RunState.PLANNED,
            provider_run_ref=provider_run_ref,
            plan=plan_out,
            transcript=f"Resources allocated. Workspace: {workspace}",
        )

    def boot(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._active_containers.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        plan = info["plan"]
        launch_mode = info.get("launch_mode", "simulated")
        if launch_mode == "dry_run":
            return ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Dry run: guest boot skipped.",
                health=HealthStatus.UNKNOWN,
            )
        if launch_mode == "simulated":
            info["state"] = RunState.COMPLETED
            return ProviderResult(
                state=RunState.COMPLETED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Simulated constrained Kali run completed with synthetic evidence export.",
                health=HealthStatus.STOPPED,
            )
        container_name = info["container_name"]
        docker_args = list(plan.get("docker_args", []))
        docker_args.insert(2, "--name")
        docker_args.insert(3, container_name)
        if "--rm" in docker_args:
            docker_args[docker_args.index("--rm")] = "--detach"

        try:
            result = subprocess.run(docker_args, capture_output=True, text=True, timeout=LAUNCH_TIMEOUT_SECONDS)
            if result.returncode != 0:
                return ProviderResult(
                    state=RunState.ERRORED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript=f"Boot failed: {result.stderr.strip()}",
                    error=result.stderr.strip(),
                )
            container_id = result.stdout.strip()[:12]
            info["container_id"] = container_id
            info["state"] = RunState.RUNNING
            return ProviderResult(
                state=RunState.RUNNING,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript=f"Container {container_name} booted ({container_id}).",
                container_id=container_id,
                health=HealthStatus.BOOTING,
            )
        except subprocess.TimeoutExpired:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Boot timed out.",
                error="boot_timeout",
                retry_after_seconds=30,
            )

    def health(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._active_containers.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
                health=HealthStatus.UNKNOWN,
            )
        container_id = info.get("container_id")
        if not container_id:
            return ProviderResult(
                state=info.get("state", RunState.PLANNED),
                provider_run_ref=provider_run_ref,
                health=HealthStatus.UNKNOWN,
                transcript="No container yet.",
            )
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container_id],
                capture_output=True, text=True, timeout=10,
            )
            status = result.stdout.strip()
            health_map = {
                "running": HealthStatus.READY,
                "created": HealthStatus.BOOTING,
                "restarting": HealthStatus.UNHEALTHY,
                "paused": HealthStatus.UNHEALTHY,
                "exited": HealthStatus.STOPPED,
                "dead": HealthStatus.ERRORED,
                "removing": HealthStatus.DESTROYED,
            }
            h = health_map.get(status, HealthStatus.UNKNOWN)
            state_map = {
                HealthStatus.READY: RunState.RUNNING,
                HealthStatus.BOOTING: RunState.BOOTING,
                HealthStatus.STOPPED: RunState.STOPPED,
                HealthStatus.ERRORED: RunState.ERRORED,
                HealthStatus.DESTROYED: RunState.DESTROYED,
                HealthStatus.UNHEALTHY: RunState.UNHEALTHY,
            }
            rs = state_map.get(h, info.get("state", RunState.RUNNING))
            return ProviderResult(
                state=rs,
                provider_run_ref=provider_run_ref,
                health=h,
                transcript=f"Container status: {status}",
                container_id=container_id,
            )
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return ProviderResult(
                state=RunState.UNHEALTHY,
                provider_run_ref=provider_run_ref,
                health=HealthStatus.UNKNOWN,
                transcript="Health check failed.",
                error="health_check_failed",
            )

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        info = self._active_containers.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        container_id = info.get("container_id")
        if not container_id:
            return ProviderResult(
                state=RunState.STOPPED,
                provider_run_ref=provider_run_ref,
                transcript="No container to stop.",
            )
        try:
            subprocess.run(
                ["docker", "stop", container_id],
                capture_output=True, text=True, timeout=30,
            )
            info["state"] = RunState.STOPPED
            return ProviderResult(
                state=RunState.STOPPED,
                provider_run_ref=provider_run_ref,
                transcript=f"Container {container_id} stopped.",
                container_id=container_id,
                health=HealthStatus.STOPPED,
            )
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript=f"Stop failed: {exc}",
                error=str(exc),
            )

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        info = self._active_containers.get(provider_run_ref)
        if info is None:
            return ProviderResult(
                state=RunState.ERRORED,
                provider_run_ref=provider_run_ref,
                transcript="Unknown run reference.",
                error="unknown_ref",
            )
        container_id = info.get("container_id")
        if container_id:
            try:
                subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, text=True, timeout=15)
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                logger.warning("Failed to remove container %s during teardown", container_id)

        workspace = info.get("workspace", "")
        cleanup_msg = ""
        if workspace and os.path.isdir(workspace) and not retain_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
            cleanup_msg = f" Workspace {workspace} removed."
        elif retain_workspace:
            cleanup_msg = f" Workspace {workspace} retained."

        info["state"] = RunState.DESTROYED
        return ProviderResult(
            state=RunState.DESTROYED,
            provider_run_ref=provider_run_ref,
            transcript=f"Teardown complete.{cleanup_msg}",
            health=HealthStatus.DESTROYED,
        )

    def destroy(self, *, provider_run_ref: str) -> ProviderResult:
        result = self.teardown(provider_run_ref=provider_run_ref, retain_workspace=False)
        self._active_containers.pop(provider_run_ref, None)
        return result

    def transfer_artifacts(
        self,
        *,
        provider_run_ref: str,
        artifacts: List[Dict[str, Any]],
        workspace_path: str,
    ) -> Dict[str, Any]:
        os.makedirs(workspace_path, exist_ok=True)
        results: List[Dict[str, Any]] = []
        for artifact in artifacts:
            src = artifact.get("source_path", "")
            name = artifact.get("name", os.path.basename(src))
            requested_destination = str(artifact.get("destination") or f"/workspace/{name}")
            relative_destination = requested_destination
            if requested_destination.startswith("/workspace/"):
                relative_destination = requested_destination[len("/workspace/"):]
            elif requested_destination == "/workspace":
                relative_destination = name
            relative_destination = relative_destination.lstrip("/") or name
            dst = os.path.join(workspace_path, relative_destination)
            if not src or not os.path.isfile(src):
                results.append({"name": name, "status": "missing", "error": "source not found"})
                continue

            pre_hash = self._file_sha256(src)
            expected_hash = artifact.get("sha256") or artifact.get("expected_sha256")
            if expected_hash and pre_hash != str(expected_hash).lower():
                results.append(
                    {
                        "name": name,
                        "status": "checksum_mismatch",
                        "pre_hash": pre_hash,
                        "expected_sha256": str(expected_hash).lower(),
                    }
                )
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            post_hash = self._file_sha256(dst)
            if pre_hash != post_hash:
                os.remove(dst)
                results.append({"name": name, "status": "checksum_mismatch", "pre_hash": pre_hash, "post_hash": post_hash})
                continue

            results.append(
                {
                    "name": name,
                    "status": "transferred",
                    "sha256": post_hash,
                    "destination": requested_destination,
                    "host_path": dst,
                }
            )

        return {"provider_run_ref": provider_run_ref, "transfers": results}

    def _docker_args_for_plan(self, plan: Dict[str, Any], *, host_workspace: Optional[str] = None) -> List[str]:
        args = [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network",
            plan["network_mode"],
            "--user",
            plan["user"],
            "--workdir",
            plan["workdir"],
        ]
        for opt in plan["security_options"]:
            args.extend(["--security-opt", opt])
        for cap in plan["cap_drop"]:
            args.extend(["--cap-drop", cap])
        for cap in plan["cap_add"]:
            args.extend(["--cap-add", cap])
        for mount in plan["tmpfs_mounts"]:
            args.extend(["--tmpfs", mount])
        workspace = host_workspace or plan.get("host_workspace")
        workspace_target = plan.get("workspace_mount_target") or plan.get("workdir") or "/workspace"
        if workspace:
            args.extend(["-v", f"{workspace}:{workspace_target}"])
        args.append(plan["image"])
        args.extend(plan["command"])
        return args

    def _provider_readiness(self, *, image: str, network_mode: str, collectors: List[str]) -> Dict[str, Any]:
        docker_cli = shutil.which("docker") is not None
        docker_version_ok = False
        docker_version_error: Optional[str] = None
        if docker_cli:
            try:
                subprocess.run(["docker", "version"], check=True, capture_output=True, text=True, timeout=15)
                docker_version_ok = True
            except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as exc:
                docker_version_error = str(exc)
        image_present = False
        image_error: Optional[str] = None
        if docker_version_ok:
            try:
                result = subprocess.run(
                    ["docker", "image", "inspect", image],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                image_present = result.returncode == 0
                if result.returncode != 0:
                    image_error = (result.stderr or "").strip() or "image_not_present_locally"
            except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as exc:
                image_error = str(exc)
        workspace_root_ready = self._safe_workspace_root_ready()
        tooling_profile = self._tooling_profile_for_image(image)
        osquery_requested = "osquery_snapshot" in set(collectors or [])
        tracee_requested = "tracee_events" in set(collectors or [])
        checks = [
            {
                "name": "docker_cli",
                "status": "ready" if docker_cli else "unavailable",
                "detail": "Docker CLI available on host." if docker_cli else "Docker CLI not found on host.",
            },
            {
                "name": "docker_engine",
                "status": "ready" if docker_version_ok else "unavailable",
                "detail": "Docker engine responded to version check." if docker_version_ok else (docker_version_error or "Docker engine not reachable."),
            },
            {
                "name": "image_local",
                "status": "ready" if image_present else "degraded",
                "detail": f"Image {image} present locally." if image_present else (image_error or f"Image {image} not present locally; Docker may pull it during boot."),
            },
            {
                "name": "image_profile",
                "status": "ready",
                "detail": f"Image profile resolves to {tooling_profile['profile']}.",
            },
            {
                "name": "workspace_root",
                "status": "ready" if workspace_root_ready else "unavailable",
                "detail": f"Workspace root {WORKSPACE_ROOT} is writable." if workspace_root_ready else f"Workspace root {WORKSPACE_ROOT} is not writable.",
            },
            {
                "name": "teardown_policy",
                "status": "ready",
                "detail": "Ephemeral teardown path supported for constrained Docker workspaces.",
            },
            {
                "name": "network_mode",
                "status": "ready" if network_mode in ALLOWED_NETWORK_MODES else "degraded",
                "detail": f"Requested network mode resolves to {network_mode}.",
            },
        ]
        if osquery_requested:
            checks.append(
                {
                    "name": "osquery_image_support",
                    "status": "ready" if tooling_profile["osquery_available"] else "unavailable",
                    "detail": (
                        f"Image {image} is marked osquery-capable."
                        if tooling_profile["osquery_available"]
                        else f"Collector osquery_snapshot requires an osquery-capable image such as {DEFAULT_OSQUERY_IMAGE}."
                    ),
                }
            )
        if tracee_requested:
            checks.append(
                {
                    "name": "tracee_image_support",
                    "status": "ready" if tooling_profile["tracee_available"] else "unavailable",
                    "detail": (
                        f"Image {image} is marked Tracee-capable."
                        if tooling_profile["tracee_available"]
                        else f"Collector tracee_events requires a Tracee-capable image such as {DEFAULT_TRACEE_IMAGE}."
                    ),
                }
            )
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
            "workspace_root": WORKSPACE_ROOT,
        }

    def _collector_capabilities(self, *, collectors: List[str], image: str) -> List[Dict[str, Any]]:
        selected = set(collectors or [])
        docker_ready = shutil.which("docker") is not None
        tooling_profile = self._tooling_profile_for_image(image)
        capabilities: List[Dict[str, Any]] = []

        for name in BASELINE_EXECUTE_COLLECTORS:
            capabilities.append(
                {
                    "collector_name": name,
                    "tier": "baseline",
                    "selected": name in selected,
                    "status": "ready" if docker_ready else "unavailable",
                    "reason": "Execute-mode default collector." if docker_ready else "Docker CLI unavailable on host.",
                    "requires_feature_flag": False,
                }
            )

        env_requirements = {
            "osquery_snapshot": {"feature_flag": None, "guest_tool": "osqueryi"},
            "tracee_events": {"feature_flag": None, "guest_tool": "tracee"},
            "falco_events": {"feature_flag": "SHESHNAAG_ENABLE_FALCO", "guest_tool": "falco"},
            "tetragon_events": {"feature_flag": "SHESHNAAG_ENABLE_TETRAGON", "guest_tool": "tetra"},
            "pcap": {"feature_flag": None, "guest_tool": "tcpdump"},
        }
        for name in EXTENDED_EXECUTE_COLLECTORS:
            requirement = env_requirements[name]
            flag = requirement["feature_flag"]
            flag_enabled = True if flag is None else os.environ.get(flag, "").strip().lower() in {"1", "true", "yes", "on"}
            status = "ready" if docker_ready and flag_enabled else "degraded"
            reason = "Optional execute collector is enabled." if status == "ready" else (
                f"Enable {flag} to promote this collector from degraded to ready." if flag and not flag_enabled else "Docker CLI unavailable on host."
            )
            if name == "osquery_snapshot" and not tooling_profile["osquery_available"]:
                status = "unavailable"
                reason = f"osquery_snapshot requires an osquery-capable image such as {DEFAULT_OSQUERY_IMAGE}."
            if name == "tracee_events":
                if tooling_profile["tracee_available"]:
                    status = "ready" if docker_ready else "unavailable"
                    reason = "Tracee is a supported advanced collector when a trusted Tracee-capable image is selected."
                else:
                    status = "unavailable"
                    reason = f"tracee_events requires a Tracee-capable image such as {DEFAULT_TRACEE_IMAGE}."
            if name == "pcap":
                status = "unavailable"
                reason = "PCAP capture is restricted to secure-mode Lima runs in v2."
            capabilities.append(
                {
                    "collector_name": name,
                    "tier": "supported" if name == "tracee_events" else "extended",
                    "selected": name in selected,
                    "status": status,
                    "reason": reason,
                    "requires_feature_flag": bool(flag),
                    "feature_flag": flag,
                    "guest_tool": requirement["guest_tool"],
                }
            )
        return capabilities

    @staticmethod
    def _tooling_profile_for_image(image: str) -> Dict[str, Any]:
        entry = find_image_by_name(image, provider="docker_kali")
        normalized = (image or "").strip().lower()
        osquery_available = bool(entry.supports_osquery) if entry else normalized == DEFAULT_OSQUERY_IMAGE.lower() or "osquery" in normalized
        tracee_available = bool(entry.supports_tracee) if entry else normalized == DEFAULT_TRACEE_IMAGE.lower() or "tracee" in normalized
        if tracee_available:
            profile = "tracee"
        elif osquery_available:
            profile = "osquery"
        else:
            profile = "baseline"
        return {
            "profile": profile,
            "osquery_available": osquery_available,
            "tracee_available": tracee_available,
        }

    @staticmethod
    def _digest_value(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _generate_run_ref() -> str:
        return f"docker-kali-{uuid.uuid4().hex[:10]}"

    @staticmethod
    def _container_name(provider_run_ref: str) -> str:
        return f"sheshnaag-{provider_run_ref}"

    @staticmethod
    def _workspace_for_ref(provider_run_ref: str) -> str:
        return os.path.join(WORKSPACE_ROOT, provider_run_ref)

    @staticmethod
    def _safe_workspace_root_ready() -> bool:
        try:
            os.makedirs(WORKSPACE_ROOT, exist_ok=True)
            return os.access(WORKSPACE_ROOT, os.W_OK)
        except OSError:
            return False

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
