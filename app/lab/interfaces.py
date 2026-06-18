"""Core interfaces for lab providers, collectors, artifacts, and attestation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from enum import Enum
from typing import Any

VALID_LAUNCH_MODES = {"dry_run", "simulated", "execute"}


class RunState(str, Enum):
    """Canonical run lifecycle states."""

    PLANNED = "planned"
    BOOTING = "booting"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    TEARING_DOWN = "tearing_down"
    DESTROYED = "destroyed"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    ERRORED = "errored"
    UNHEALTHY = "unhealthy"


class HealthStatus(str, Enum):
    """Guest health vocabulary."""

    BOOTING = "booting"
    READY = "ready"
    UNHEALTHY = "unhealthy"
    STOPPED = "stopped"
    DESTROYED = "destroyed"
    ERRORED = "errored"
    UNKNOWN = "unknown"


VALID_TRANSITIONS: dict[RunState, list[RunState]] = {
    RunState.PLANNED: [RunState.BOOTING, RunState.BLOCKED, RunState.ERRORED],
    RunState.BOOTING: [RunState.READY, RunState.RUNNING, RunState.ERRORED, RunState.UNHEALTHY],
    RunState.READY: [RunState.RUNNING, RunState.STOPPING, RunState.ERRORED],
    RunState.RUNNING: [RunState.COMPLETED, RunState.STOPPING, RunState.ERRORED, RunState.UNHEALTHY],
    RunState.STOPPING: [RunState.STOPPED, RunState.ERRORED],
    RunState.STOPPED: [RunState.TEARING_DOWN, RunState.ERRORED],
    RunState.TEARING_DOWN: [RunState.DESTROYED, RunState.ERRORED],
    RunState.COMPLETED: [RunState.TEARING_DOWN],
    RunState.BLOCKED: [],
    RunState.ERRORED: [RunState.TEARING_DOWN],
    RunState.UNHEALTHY: [RunState.STOPPING, RunState.TEARING_DOWN, RunState.ERRORED],
    RunState.DESTROYED: [],
}


class ProviderResult:
    """Normalized result payload returned by every provider lifecycle method."""

    def __init__(
        self,
        *,
        state: RunState,
        provider_run_ref: str,
        plan: dict[str, Any] | None = None,
        transcript: str = "",
        container_id: str | None = None,
        health: HealthStatus = HealthStatus.UNKNOWN,
        error: str | None = None,
        retry_after_seconds: int | None = None,
    ):
        self.state = state
        self.provider_run_ref = provider_run_ref
        self.plan = plan or {}
        self.transcript = transcript
        self.container_id = container_id
        self.health = health
        self.error = error
        self.retry_after_seconds = retry_after_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "provider_run_ref": self.provider_run_ref,
            "plan": self.plan,
            "transcript": self.transcript,
            "container_id": self.container_id,
            "health": self.health.value,
            "error": self.error,
            "retry_after_seconds": self.retry_after_seconds,
        }


def validate_transition(current: RunState, target: RunState) -> bool:
    """Return True if the transition from *current* to *target* is legal."""
    return target in VALID_TRANSITIONS.get(current, [])


def normalize_launch_mode(value: str | None) -> str:
    """Normalize launch-mode aliases to the canonical wire/storage contract."""
    normalized = (value or "simulated").strip().lower().replace("-", "_")
    if normalized == "live":
        return "execute"
    if normalized not in VALID_LAUNCH_MODES:
        raise ValueError(
            f"Invalid launch mode '{value}'. Expected one of dry_run, simulated, execute."
        )
    return normalized


class LabProvider(ABC):
    """Provider abstraction for validation environments."""

    provider_name: str = "unknown"

    @abstractmethod
    def build_plan(
        self, *, revision_content: dict[str, Any], run_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Return a launch and safety plan for a run."""

    @abstractmethod
    def launch(
        self, *, revision_content: dict[str, Any], run_context: dict[str, Any]
    ) -> ProviderResult:
        """Launch a run or return a simulated launch result."""

    def create(self, *, plan: dict[str, Any], run_context: dict[str, Any]) -> ProviderResult:
        """Allocate resources for a run without starting execution."""
        raise NotImplementedError(f"{self.provider_name} does not implement create")

    def boot(self, *, provider_run_ref: str) -> ProviderResult:
        """Start the guest environment."""
        raise NotImplementedError(f"{self.provider_name} does not implement boot")

    def health(self, *, provider_run_ref: str) -> ProviderResult:
        """Return current guest health status."""
        raise NotImplementedError(f"{self.provider_name} does not implement health")

    def stop(self, *, provider_run_ref: str) -> ProviderResult:
        """Gracefully stop the running guest."""
        raise NotImplementedError(f"{self.provider_name} does not implement stop")

    def teardown(self, *, provider_run_ref: str, retain_workspace: bool = False) -> ProviderResult:
        """Release execution resources but optionally retain the workspace."""
        raise NotImplementedError(f"{self.provider_name} does not implement teardown")

    def destroy(self, *, provider_run_ref: str) -> ProviderResult:
        """Destroy all resources including workspace data."""
        raise NotImplementedError(f"{self.provider_name} does not implement destroy")

    def transfer_artifacts(
        self,
        *,
        provider_run_ref: str,
        artifacts: list[dict[str, Any]],
        workspace_path: str,
    ) -> dict[str, Any]:
        """Copy input artifacts into the guest workspace and return checksums."""
        raise NotImplementedError(f"{self.provider_name} does not implement transfer_artifacts")


class Collector(ABC):
    """Collector abstraction for evidence pipelines."""

    collector_name: str = "unknown"
    collector_version: str = "0.0.0"

    def pre_run(self, *, run_context: dict[str, Any], provider_result: dict[str, Any]) -> None:
        """Optional hook before main collection (e.g. baseline snapshots)."""

    def post_run(self, *, run_context: dict[str, Any], provider_result: dict[str, Any]) -> None:
        """Optional hook after main collection."""

    @abstractmethod
    def collect(
        self, *, run_context: dict[str, Any], provider_result: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Collect normalized evidence artifacts."""


class ArtifactGenerator(ABC):
    """Generate defensive artifacts from evidence."""

    @abstractmethod
    def generate(
        self, *, run_context: dict[str, Any], evidence: Iterable[dict[str, Any]]
    ) -> dict[str, Any]:
        """Return generated defensive artifacts."""


class AttestationSigner(ABC):
    """Sign or attest run and bundle manifests."""

    @abstractmethod
    def sign(self, *, payload: dict[str, Any], signer: str) -> dict[str, str]:
        """Return attestation metadata for a payload."""
