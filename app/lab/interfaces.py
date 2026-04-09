"""Core interfaces for lab providers, collectors, artifacts, and attestation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


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


VALID_TRANSITIONS: Dict[RunState, List[RunState]] = {
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
        plan: Optional[Dict[str, Any]] = None,
        transcript: str = "",
        container_id: Optional[str] = None,
        health: HealthStatus = HealthStatus.UNKNOWN,
        error: Optional[str] = None,
        retry_after_seconds: Optional[int] = None,
    ):
        self.state = state
        self.provider_run_ref = provider_run_ref
        self.plan = plan or {}
        self.transcript = transcript
        self.container_id = container_id
        self.health = health
        self.error = error
        self.retry_after_seconds = retry_after_seconds

    def to_dict(self) -> Dict[str, Any]:
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


class LabProvider(ABC):
    """Provider abstraction for validation environments."""

    provider_name: str = "unknown"

    @abstractmethod
    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        """Return a launch and safety plan for a run."""

    @abstractmethod
    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
        """Launch a run or return a simulated launch result."""

    def create(self, *, plan: Dict[str, Any], run_context: Dict[str, Any]) -> ProviderResult:
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
        artifacts: List[Dict[str, Any]],
        workspace_path: str,
    ) -> Dict[str, Any]:
        """Copy input artifacts into the guest workspace and return checksums."""
        raise NotImplementedError(f"{self.provider_name} does not implement transfer_artifacts")


class Collector(ABC):
    """Collector abstraction for evidence pipelines."""

    collector_name: str = "unknown"
    collector_version: str = "0.0.0"

    def pre_run(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> None:
        """Optional hook before main collection (e.g. baseline snapshots)."""

    def post_run(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> None:
        """Optional hook after main collection."""

    @abstractmethod
    def collect(self, *, run_context: Dict[str, Any], provider_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect normalized evidence artifacts."""


class ArtifactGenerator(ABC):
    """Generate defensive artifacts from evidence."""

    @abstractmethod
    def generate(self, *, run_context: Dict[str, Any], evidence: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        """Return generated defensive artifacts."""


class AttestationSigner(ABC):
    """Sign or attest run and bundle manifests."""

    @abstractmethod
    def sign(self, *, payload: Dict[str, Any], signer: str) -> Dict[str, str]:
        """Return attestation metadata for a payload."""
