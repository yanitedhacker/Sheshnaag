"""Real VM snapshot + rollback orchestration for Sheshnaag V4.

Each sandbox run should start from a known-good baseline and revert to that
baseline at teardown.  V3 recorded this as synthetic metadata; V4 actually
invokes the hypervisor CLI when it is available.

Providers supported:

* ``libvirt`` — ``virsh snapshot-create-as`` + ``virsh snapshot-revert``.
  Domain name comes from ``profile.config['domain']``.
* ``lima`` — ``limactl stop --force`` + cow-disk rollback.  lima instance
  name comes from ``profile.config['instance']`` (falling back to
  ``profile.name``).
* ``docker`` — lightweight: images are already immutable, each run is a
  fresh ``--rm`` container on a ``tmpfs`` volume, so revert is effectively a
  no-op.  We still capture the image digest at run start for provenance.

The module is importable without ``libvirt``, ``virsh`` or ``limactl``
present on the host; missing binaries downgrade the manager to ``dry_run``.
The ``with_snapshot`` context manager **always** attempts to revert on
exit, even when the body raised, unless ``SHESHNAAG_SNAPSHOT_NO_REVERT=1``
is set (primarily a developer-loop escape hatch).
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from app.core.time import utc_now

logger = logging.getLogger(__name__)

__all__ = ["SnapshotManager", "SUPPORTED_PROVIDERS"]

SUPPORTED_PROVIDERS: tuple[str, ...] = ("libvirt", "lima", "docker")

_BASELINE_TAG = "sheshnaag-baseline"
_LIMA_COW_SUFFIX = ".baseline.qcow2"


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


class SnapshotManager:
    """Orchestrate snapshot/revert for a single run.

    Parameters
    ----------
    profile:
        The :class:`SandboxProfile` row backing this run.  Read-only; we look
        at ``profile.provider_hint``, ``profile.config`` and ``profile.name``.
    run_id:
        The ``LabRun.id``; used as a handle in snapshot tags so different
        runs don't alias each other's snapshots.
    provider:
        Override the provider discovered from ``profile.provider_hint``.
    """

    def __init__(
        self,
        profile: Any,
        *,
        run_id: Any,
        provider: Optional[str] = None,
    ) -> None:
        self._profile = profile
        self._run_id = run_id
        self._run_tag = f"sheshnaag-{run_id}-{uuid.uuid4().hex[:8]}"
        self._config: Dict[str, Any] = dict(getattr(profile, "config", None) or {})

        resolved_provider = (provider or getattr(profile, "provider_hint", "") or "").strip().lower()
        if resolved_provider not in SUPPORTED_PROVIDERS:
            logger.warning(
                "snapshot_manager.unknown_provider",
                extra={"provider": resolved_provider, "falling_back_to": "docker"},
            )
            resolved_provider = "docker"
        self._provider = resolved_provider
        self._events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def events(self) -> List[Dict[str, Any]]:
        return list(self._events)

    @contextmanager
    def with_snapshot(self) -> Iterator[Dict[str, Any]]:
        """Capture a snapshot, yield handle, revert on exit.

        Yields
        ------
        dict
            ``{"snapshot_id", "provider", "baseline_sha", "created_at",
            "revert_on_exit"}`` plus provider-specific metadata in
            ``"details"``.
        """
        no_revert = _bool_env("SHESHNAAG_SNAPSHOT_NO_REVERT")
        created = self._create_snapshot()
        handle = {
            "snapshot_id": created["snapshot_id"],
            "provider": self._provider,
            "baseline_sha": created["baseline_sha"],
            "created_at": created["created_at"],
            "revert_on_exit": not no_revert,
            "dry_run": created.get("dry_run", False),
            "details": created.get("details", {}),
            "errors": list(created.get("errors", [])),
        }
        self._events.append({"event": "snapshot_created", "at": utc_now().isoformat(), **created})
        try:
            yield handle
        finally:
            if no_revert:
                self._events.append(
                    {
                        "event": "snapshot_revert_skipped",
                        "at": utc_now().isoformat(),
                        "reason": "SHESHNAAG_SNAPSHOT_NO_REVERT",
                        "snapshot_id": handle["snapshot_id"],
                    }
                )
                logger.info(
                    "snapshot_manager.revert_skipped",
                    extra={"run_id": str(self._run_id), "snapshot_id": handle["snapshot_id"]},
                )
            else:
                revert_result = self._revert_snapshot(handle)
                self._events.append(
                    {
                        "event": "snapshot_reverted",
                        "at": utc_now().isoformat(),
                        **revert_result,
                    }
                )

    # ------------------------------------------------------------------
    # Provider dispatch
    # ------------------------------------------------------------------

    def _create_snapshot(self) -> Dict[str, Any]:
        if self._provider == "libvirt":
            return self._libvirt_snapshot(action="create")
        if self._provider == "lima":
            return self._lima_snapshot(action="create")
        return self._docker_snapshot(action="create")

    def _revert_snapshot(self, handle: Dict[str, Any]) -> Dict[str, Any]:
        if self._provider == "libvirt":
            return self._libvirt_snapshot(action="revert", handle=handle)
        if self._provider == "lima":
            return self._lima_snapshot(action="revert", handle=handle)
        return self._docker_snapshot(action="revert", handle=handle)

    # ------------------------------------------------------------------
    # libvirt provider
    # ------------------------------------------------------------------

    def _libvirt_snapshot(
        self,
        *,
        action: str,
        handle: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        domain = str(self._config.get("domain") or getattr(self._profile, "name", "")).strip()
        errors: List[str] = []
        if not domain:
            errors.append("libvirt provider requires profile.config['domain'] to be set")

        if not self._binary_ok("virsh"):
            return self._dry_result(
                action=action,
                snapshot_id=(handle or {}).get("snapshot_id") or f"{self._run_tag}:{_BASELINE_TAG}",
                reason="virsh not available",
                details={"domain": domain},
                errors=errors,
            )

        if errors:
            return self._dry_result(
                action=action,
                snapshot_id=(handle or {}).get("snapshot_id") or f"{self._run_tag}:{_BASELINE_TAG}",
                reason="libvirt config invalid",
                details={"domain": domain},
                errors=errors,
            )

        snapshot_name = (handle or {}).get("snapshot_id") or f"{self._run_tag}-{_BASELINE_TAG}"

        if action == "create":
            cmd = [
                "virsh",
                "snapshot-create-as",
                domain,
                snapshot_name,
                "--atomic",
                "--no-metadata",
            ]
            proc = self._run(cmd, timeout=120)
            if proc["returncode"] != 0:
                errors.append(f"virsh snapshot-create-as failed: {proc['stderr'][:400]}")
            return {
                "snapshot_id": snapshot_name,
                "provider": self._provider,
                "baseline_sha": self._digest(f"libvirt:{domain}:{snapshot_name}"),
                "created_at": utc_now().isoformat(),
                "dry_run": False,
                "details": {"domain": domain, "stdout": proc["stdout"], "stderr": proc["stderr"]},
                "errors": errors,
            }

        # revert
        cmd = ["virsh", "snapshot-revert", domain, snapshot_name, "--force"]
        proc = self._run(cmd, timeout=180)
        if proc["returncode"] != 0:
            errors.append(f"virsh snapshot-revert failed: {proc['stderr'][:400]}")
        # Best-effort delete of the snapshot after revert so we don't leak.
        self._run(["virsh", "snapshot-delete", domain, snapshot_name], timeout=60)
        return {
            "snapshot_id": snapshot_name,
            "provider": self._provider,
            "action": "revert",
            "details": {"domain": domain, "stdout": proc["stdout"], "stderr": proc["stderr"]},
            "errors": errors,
            "dry_run": False,
            "reverted_at": utc_now().isoformat(),
        }

    # ------------------------------------------------------------------
    # lima provider
    # ------------------------------------------------------------------

    def _lima_snapshot(
        self,
        *,
        action: str,
        handle: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        instance = str(
            self._config.get("instance")
            or self._config.get("lima_instance")
            or getattr(self._profile, "name", "")
            or ""
        ).strip()
        disk_path = str(self._config.get("disk_path") or "").strip()
        errors: List[str] = []
        if not instance:
            errors.append("lima provider requires profile.config['instance'] or profile.name")

        if not self._binary_ok("limactl"):
            return self._dry_result(
                action=action,
                snapshot_id=(handle or {}).get("snapshot_id") or f"{self._run_tag}:{_BASELINE_TAG}",
                reason="limactl not available",
                details={"instance": instance, "disk_path": disk_path},
                errors=errors,
            )

        snapshot_name = (handle or {}).get("snapshot_id") or f"{self._run_tag}-{_BASELINE_TAG}"
        baseline_image = self._lima_baseline_image(disk_path)

        if action == "create":
            # Stop the instance first so cow snapshot is consistent.
            stop = self._run(["limactl", "stop", "--force", instance], timeout=60)
            if stop["returncode"] not in (0, 1):
                # exit 1 often just means "already stopped" — tolerate it.
                errors.append(f"limactl stop --force failed: {stop['stderr'][:400]}")

            cow_err = self._lima_capture_baseline(disk_path=disk_path, baseline_image=baseline_image)
            if cow_err:
                errors.append(cow_err)
            return {
                "snapshot_id": snapshot_name,
                "provider": self._provider,
                "baseline_sha": self._digest(f"lima:{instance}:{baseline_image or snapshot_name}"),
                "created_at": utc_now().isoformat(),
                "dry_run": False,
                "details": {
                    "instance": instance,
                    "disk_path": disk_path,
                    "baseline_image": baseline_image,
                    "stop_stdout": stop["stdout"],
                    "stop_stderr": stop["stderr"],
                },
                "errors": errors,
            }

        # revert: stop, restore cow, leave user to restart on next run.
        stop = self._run(["limactl", "stop", "--force", instance], timeout=60)
        if stop["returncode"] not in (0, 1):
            errors.append(f"limactl stop --force failed during revert: {stop['stderr'][:400]}")
        cow_err = self._lima_restore_baseline(disk_path=disk_path, baseline_image=baseline_image)
        if cow_err:
            errors.append(cow_err)
        return {
            "snapshot_id": snapshot_name,
            "provider": self._provider,
            "action": "revert",
            "details": {
                "instance": instance,
                "disk_path": disk_path,
                "baseline_image": baseline_image,
                "stop_stdout": stop["stdout"],
                "stop_stderr": stop["stderr"],
            },
            "errors": errors,
            "dry_run": False,
            "reverted_at": utc_now().isoformat(),
        }

    @staticmethod
    def _lima_baseline_image(disk_path: str) -> str:
        if not disk_path:
            return ""
        return disk_path + _LIMA_COW_SUFFIX

    def _lima_capture_baseline(self, *, disk_path: str, baseline_image: str) -> Optional[str]:
        if not disk_path or not baseline_image:
            return None
        if not os.path.isfile(disk_path):
            return f"lima disk image missing at {disk_path}; baseline not captured"
        if os.path.isfile(baseline_image):
            # Baseline already captured by a previous run; keep it.
            return None
        try:
            shutil.copy2(disk_path, baseline_image)
        except OSError as exc:
            return f"failed to copy baseline image: {exc}"
        return None

    def _lima_restore_baseline(self, *, disk_path: str, baseline_image: str) -> Optional[str]:
        if not disk_path or not baseline_image:
            return None
        if not os.path.isfile(baseline_image):
            return f"no baseline image at {baseline_image}; revert skipped"
        try:
            shutil.copy2(baseline_image, disk_path)
        except OSError as exc:
            return f"failed to restore baseline image: {exc}"
        return None

    # ------------------------------------------------------------------
    # docker provider
    # ------------------------------------------------------------------

    def _docker_snapshot(
        self,
        *,
        action: str,
        handle: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        image = str(self._config.get("image") or "").strip()
        errors: List[str] = []
        snapshot_id = (handle or {}).get("snapshot_id") or f"{self._run_tag}-docker"

        if not self._binary_ok("docker"):
            return self._dry_result(
                action=action,
                snapshot_id=snapshot_id,
                reason="docker not available",
                details={"image": image},
                errors=errors,
            )

        digest = ""
        if image and action == "create":
            proc = self._run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                timeout=15,
            )
            if proc["returncode"] == 0:
                digest = proc["stdout"].strip()
            else:
                errors.append(
                    f"docker image inspect failed for {image}: {proc['stderr'][:200]}"
                )

        if action == "create":
            return {
                "snapshot_id": snapshot_id,
                "provider": self._provider,
                "baseline_sha": digest or self._digest(f"docker:{image}:{snapshot_id}"),
                "created_at": utc_now().isoformat(),
                "dry_run": False,
                "details": {
                    "image": image,
                    "image_digest": digest,
                    "strategy": "ephemeral_container_on_tmpfs",
                    "revert_is_noop": True,
                    "enforced_run_flags": ["--rm", "--tmpfs=/tmp", "--tmpfs=/var/tmp"],
                },
                "errors": errors,
            }

        # Revert: no-op for docker; every run gets a fresh --rm container.
        return {
            "snapshot_id": snapshot_id,
            "provider": self._provider,
            "action": "revert",
            "details": {
                "image": image,
                "strategy": "ephemeral_container_on_tmpfs",
                "revert_is_noop": True,
            },
            "errors": errors,
            "dry_run": False,
            "reverted_at": utc_now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _binary_ok(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _dry_result(
        self,
        *,
        action: str,
        snapshot_id: str,
        reason: str,
        details: Dict[str, Any],
        errors: List[str],
    ) -> Dict[str, Any]:
        logger.info(
            "snapshot_manager.dry_run",
            extra={
                "run_id": str(self._run_id),
                "provider": self._provider,
                "action": action,
                "reason": reason,
            },
        )
        base = {
            "snapshot_id": snapshot_id,
            "provider": self._provider,
            "dry_run": True,
            "details": {**details, "reason": reason},
            "errors": errors,
        }
        if action == "create":
            base["baseline_sha"] = self._digest(f"{self._provider}:{snapshot_id}")
            base["created_at"] = utc_now().isoformat()
        else:
            base["action"] = "revert"
            base["reverted_at"] = utc_now().isoformat()
        return base

    @staticmethod
    def _run(cmd: List[str], *, timeout: int) -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "").strip(),
                "stderr": (proc.stderr or "").strip(),
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "returncode": 124,
                "stdout": "",
                "stderr": f"timeout after {timeout}s: {exc}",
            }
        except (subprocess.SubprocessError, OSError) as exc:
            return {"returncode": 1, "stdout": "", "stderr": str(exc)}
