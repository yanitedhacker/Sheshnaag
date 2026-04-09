"""Host-side execution helpers for guest-bound collectors."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional, Tuple


def docker_cli_available() -> bool:
    return shutil.which("docker") is not None


def run_in_container(
    container_id: str,
    argv: List[str],
    *,
    timeout_sec: int = 90,
    stdin_text: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run argv inside the container (docker CLI on host)."""
    cmdline = ["docker", "exec", container_id, *argv]
    try:
        proc = subprocess.run(
            cmdline,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            input=stdin_text,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, "", str(exc)


def resolve_container_id(provider_result: dict) -> Optional[str]:
    cid = provider_result.get("container_id")
    if cid:
        return str(cid)
    plan = provider_result.get("plan") or {}
    c = plan.get("container_id")
    return str(c) if c else None


def resolve_host_workspace(provider_result: dict) -> Optional[str]:
    plan = provider_result.get("plan") or {}
    path = plan.get("host_workspace")
    if path and os.path.isdir(path):
        return path
    return str(path) if path else None


def is_executable_guest_context(*, run_context: dict, provider_result: dict) -> bool:
    if run_context.get("launch_mode") != "execute":
        return False
    if not docker_cli_available():
        return False
    return bool(resolve_container_id(provider_result))


def env_flag_enabled(name: str, default: bool = False) -> bool:
    val = os.environ.get(name, "").strip().lower()
    if val in ("1", "true", "yes", "on"):
        return True
    if val in ("0", "false", "no", "off"):
        return False
    return default
