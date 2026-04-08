"""Core interfaces for lab providers, collectors, artifacts, and attestation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List


class LabProvider(ABC):
    """Provider abstraction for validation environments."""

    provider_name: str = "unknown"

    @abstractmethod
    def build_plan(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        """Return a launch and safety plan for a run."""

    @abstractmethod
    def launch(self, *, revision_content: Dict[str, Any], run_context: Dict[str, Any]) -> Dict[str, Any]:
        """Launch a run or return a simulated launch result."""


class Collector(ABC):
    """Collector abstraction for evidence pipelines."""

    collector_name: str = "unknown"

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
