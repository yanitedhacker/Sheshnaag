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
from app.lab.interfaces import (
    HealthStatus,
    LabProvider,
    ProviderResult,
    RunState,
    validate_transition,
)

logger = logging.getLogger(__name__)

DEFAULT_KALI_IMAGE = "kalilinux/kali-rolling:2026.1"
DEFAULT_SECURITY_OPTS = [
    "no-new-privileges:true",
    "apparmor=sheshnaag-default",
    "seccomp=default",
]
DEFAULT_CAP_DROP = ["ALL"]

WORKSPACE_ROOT = os.environ.get("SHESHNAAG_WORKSPACE_ROOT", "/tmp/sheshnaag")
LAUNCH_TIMEOUT_SECONDS = int(os.environ.get("SHESHNAAG_LAUNCH_TIMEOUT", "120"))

ALLOWED_NETWORK_MODES = ("none", "bridge")


class DockerKaliProvider(LabProvider):
    """Prepare constrained Docker plans for Kali-based validation."""

    provider_name = "docker_kali"

    def __init__(self) -> None:
        self._active_containers: Dict[str, Dict[str, Any]] = {}

    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        allowlisted_hosts = revision_content.get("network_policy", {}).get("allow_egress_hosts", []) or []
        collectors = revision_content.get("collectors", []) or []
        image = revision_content.get("base_image") or DEFAULT_KALI_IMAGE
        image_digest = self._digest_value(image)

        requested_network = revision_content.get("network_policy", {}).get("mode", None)
        if requested_network and requested_network not in ALLOWED_NETWORK_MODES:
            requested_network = "none"
        network_mode = requested_network or ("none" if not allowlisted_hosts else "bridge")

        plan = {
            "provider": self.provider_name,
            "image": image,
            "image_digest": image_digest,
            "command": revision_content.get("command") or ["sleep", "1"],
            "network_mode": network_mode,
            "allow_egress_hosts": allowlisted_hosts,
            "mounts": revision_content.get("mounts", []) or [],
            "read_only_rootfs": True,
            "tmpfs_mounts": ["/tmp", "/run", "/var/tmp"],
            "security_options": DEFAULT_SECURITY_OPTS,
            "cap_drop": DEFAULT_CAP_DROP,
            "cap_add": revision_content.get("cap_add", []) or [],
            "user": revision_content.get("user") or "analyst",
            "workdir": revision_content.get("workdir") or "/workspace",
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
        return plan

    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        launch_mode = run_context.get("launch_mode") or "simulated"
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        provider_run_ref = self._generate_run_ref()
        workspace = self._workspace_for_ref(provider_run_ref)

        if launch_mode == "dry_run":
            return ProviderResult(
                state=RunState.PLANNED,
                provider_run_ref=provider_run_ref,
                plan=plan,
                transcript="Dry run only. No container started.",
                health=HealthStatus.UNKNOWN,
            )

        if launch_mode == "execute":
            if shutil.which("docker") is None:
                return ProviderResult(
                    state=RunState.BLOCKED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript="Docker CLI unavailable on host. Falling back to planned state.",
                    error="docker_not_found",
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
            docker_args = list(plan["docker_args"])
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
                        plan=plan,
                        transcript=f"Container launch failed: {stderr}",
                        error=stderr,
                    )

                container_id = result.stdout.strip()[:12]
                self._active_containers[provider_run_ref] = {
                    "container_id": container_id,
                    "container_name": container_name,
                    "workspace": workspace,
                    "plan": plan,
                    "state": RunState.RUNNING,
                }

                return ProviderResult(
                    state=RunState.RUNNING,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
                    transcript=f"Container {container_name} launched ({container_id}).",
                    container_id=container_id,
                    health=HealthStatus.BOOTING,
                )
            except subprocess.TimeoutExpired:
                return ProviderResult(
                    state=RunState.ERRORED,
                    provider_run_ref=provider_run_ref,
                    plan=plan,
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
        self._active_containers[provider_run_ref] = {
            "container_id": None,
            "container_name": self._container_name(provider_run_ref),
            "workspace": workspace,
            "plan": plan,
            "state": RunState.PLANNED,
            "launch_mode": run_context.get("launch_mode", "simulated"),
        }
        return ProviderResult(
            state=RunState.PLANNED,
            provider_run_ref=provider_run_ref,
            plan=plan,
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
            dst = os.path.join(workspace_path, name)
            if not src or not os.path.isfile(src):
                results.append({"name": name, "status": "missing", "error": "source not found"})
                continue

            pre_hash = self._file_sha256(src)
            shutil.copy2(src, dst)
            post_hash = self._file_sha256(dst)
            if pre_hash != post_hash:
                os.remove(dst)
                results.append({"name": name, "status": "checksum_mismatch", "pre_hash": pre_hash, "post_hash": post_hash})
                continue

            results.append({"name": name, "status": "transferred", "sha256": post_hash, "destination": dst})

        return {"provider_run_ref": provider_run_ref, "transfers": results}

    def _docker_args_for_plan(self, plan: Dict[str, Any]) -> List[str]:
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
        args.append(plan["image"])
        args.extend(plan["command"])
        return args

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
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
