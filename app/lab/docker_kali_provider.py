"""Constrained Kali-on-Docker provider for Sheshnaag."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import uuid
from datetime import datetime
from app.core.time import utc_now
from typing import Any, Dict, List

from app.lab.interfaces import LabProvider


DEFAULT_KALI_IMAGE = "kalilinux/kali-rolling:2026.1"
DEFAULT_SECURITY_OPTS = [
    "no-new-privileges:true",
    "apparmor=sheshnaag-default",
    "seccomp=default",
]
DEFAULT_CAP_DROP = ["ALL"]


class DockerKaliProvider(LabProvider):
    """Prepare constrained Docker plans for Kali-based validation."""

    provider_name = "docker_kali"

    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        allowlisted_hosts = revision_content.get("network_policy", {}).get("allow_egress_hosts", []) or []
        collectors = revision_content.get("collectors", []) or []
        image = revision_content.get("base_image") or DEFAULT_KALI_IMAGE
        image_digest = self._digest_value(image)

        plan = {
            "provider": self.provider_name,
            "image": image,
            "image_digest": image_digest,
            "command": revision_content.get("command") or ["sleep", "1"],
            "network_mode": "none" if not allowlisted_hosts else "bridge",
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
                "mode": "destroy_container",
                "ephemeral_workspace": True,
                "retain_export_only": True,
            },
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
        return plan

    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        launch_mode = run_context.get("launch_mode") or "simulated"
        plan = self.build_plan(revision_content=revision_content, run_context=run_context)
        provider_run_ref = f"docker-kali-{uuid.uuid4().hex[:10]}"

        if launch_mode == "dry_run":
            return {
                "state": "planned",
                "provider_run_ref": provider_run_ref,
                "plan": plan,
                "transcript": "Dry run only. No container started.",
            }

        if launch_mode == "execute":
            if shutil.which("docker") is None:
                return {
                    "state": "blocked",
                    "provider_run_ref": provider_run_ref,
                    "plan": plan,
                    "transcript": "Docker CLI unavailable on host. Falling back to planned state.",
                }
            try:
                subprocess.run(["docker", "version"], check=True, capture_output=True, text=True)
                return {
                    "state": "running",
                    "provider_run_ref": provider_run_ref,
                    "plan": plan,
                    "transcript": "Docker environment validated. Execution hook reserved for future live runs.",
                }
            except subprocess.SubprocessError as exc:
                return {
                    "state": "blocked",
                    "provider_run_ref": provider_run_ref,
                    "plan": plan,
                    "transcript": f"Docker validation failed: {exc}",
                }

        return {
            "state": "completed",
            "provider_run_ref": provider_run_ref,
            "plan": plan,
            "transcript": "Simulated constrained Kali run completed with synthetic evidence export.",
        }

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
