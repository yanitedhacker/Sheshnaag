"""Provider registry and factory for supported Sheshnaag validation backends."""

from __future__ import annotations

from typing import Dict, Iterable, Type

from app.lab.docker_kali_provider import DockerKaliProvider
from app.lab.interfaces import LabProvider
from app.lab.lima_provider import LimaProvider


SUPPORTED_PROVIDER_NAMES = ("docker_kali", "lima")


class ProviderRegistry:
    """Create providers by name and expose support metadata."""

    def __init__(self) -> None:
        self._providers: Dict[str, Type[LabProvider]] = {}

    def register(self, provider_cls: Type[LabProvider]) -> None:
        self._providers[provider_cls.provider_name] = provider_cls

    def create(self, provider_name: str) -> LabProvider:
        normalized = (provider_name or "docker_kali").strip().lower()
        provider_cls = self._providers.get(normalized)
        if provider_cls is None:
            raise ValueError(
                f"Unsupported provider '{provider_name}'. Expected one of {sorted(self._providers)}."
            )
        return provider_cls()

    def supported(self) -> Iterable[str]:
        return tuple(sorted(self._providers))


def build_default_provider_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(DockerKaliProvider)
    registry.register(LimaProvider)
    return registry
