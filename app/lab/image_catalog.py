"""Trusted Sheshnaag lab image catalog for v2 planning and deployment."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


DEFAULT_BASELINE_IMAGE = os.environ.get("SHESHNAAG_BASELINE_IMAGE", "kalilinux/kali-rolling:2026.1")
DEFAULT_OSQUERY_IMAGE = os.environ.get("SHESHNAAG_OSQUERY_IMAGE", "sheshnaag-kali-osquery:2026.1")
DEFAULT_TRACEE_IMAGE = os.environ.get("SHESHNAAG_TRACEE_IMAGE", "sheshnaag-kali-tracee:2026.1")
DEFAULT_LIMA_IMAGE = os.environ.get("SHESHNAAG_LIMA_IMAGE", "sheshnaag-lima-ubuntu:2026.1")


@dataclass(frozen=True)
class ImageCatalogEntry:
    profile: str
    provider: str
    image: str
    source: str
    build_path: str
    tooling_profile: str
    trust_status: str
    supports_osquery: bool = False
    supports_tracee: bool = False
    secure_mode_only: bool = False
    description: str = ""

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.image.encode("utf-8")).hexdigest()

    def to_manifest(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "provider": self.provider,
            "image": self.image,
            "digest": self.digest,
            "source": self.source,
            "build_path": self.build_path,
            "tooling_profile": self.tooling_profile,
            "trust_status": self.trust_status,
            "supports_osquery": self.supports_osquery,
            "supports_tracee": self.supports_tracee,
            "secure_mode_only": self.secure_mode_only,
            "description": self.description,
        }


_CATALOG: List[ImageCatalogEntry] = [
    ImageCatalogEntry(
        profile="baseline",
        provider="docker_kali",
        image=DEFAULT_BASELINE_IMAGE,
        source="lab/images/base",
        build_path="Docker Hub / pinned upstream",
        tooling_profile="baseline",
        trust_status="trusted",
        description="Baseline constrained Kali image for standard validation.",
    ),
    ImageCatalogEntry(
        profile="osquery_capable",
        provider="docker_kali",
        image=DEFAULT_OSQUERY_IMAGE,
        source="lab/images/osquery/Dockerfile",
        build_path="scripts/build_sheshnaag_osquery_image.sh",
        tooling_profile="osquery",
        trust_status="trusted",
        supports_osquery=True,
        description="Trusted Kali-derived image for osquery-backed collection.",
    ),
    ImageCatalogEntry(
        profile="tracee_capable",
        provider="docker_kali",
        image=DEFAULT_TRACEE_IMAGE,
        source="lab/images/tracee/Dockerfile",
        build_path="scripts/build_sheshnaag_tracee_image.sh",
        tooling_profile="tracee",
        trust_status="trusted",
        supports_tracee=True,
        description="Trusted Kali-derived image for Tracee-backed runtime telemetry.",
    ),
    ImageCatalogEntry(
        profile="secure_lima",
        provider="lima",
        image=DEFAULT_LIMA_IMAGE,
        source="templates/lima/sheshnaag-default.yaml",
        build_path="limactl start",
        tooling_profile="secure_baseline",
        trust_status="trusted",
        secure_mode_only=True,
        description="Trusted Lima guest baseline for secure-mode validation.",
    ),
]


def list_image_catalog() -> List[ImageCatalogEntry]:
    return list(_CATALOG)


def find_image_profile(profile: str, *, provider: Optional[str] = None) -> Optional[ImageCatalogEntry]:
    normalized = (profile or "").strip().lower()
    for entry in _CATALOG:
        if entry.profile == normalized and (provider is None or entry.provider == provider):
            return entry
    return None


def find_image_by_name(image: str, *, provider: Optional[str] = None) -> Optional[ImageCatalogEntry]:
    normalized = (image or "").strip().lower()
    for entry in _CATALOG:
        if entry.image.lower() == normalized and (provider is None or entry.provider == provider):
            return entry
    return None


def default_image_profile(*, provider: str, collectors: Iterable[str]) -> str:
    collector_names = {str(name) for name in collectors or []}
    if provider == "lima":
        return "secure_lima"
    if "tracee_events" in collector_names:
        return "tracee_capable"
    if "osquery_snapshot" in collector_names:
        return "osquery_capable"
    return "baseline"


def resolve_catalog_entry(
    *,
    provider: str,
    image_profile: Optional[str] = None,
    requested_image: Optional[str] = None,
    collectors: Iterable[str] = (),
) -> ImageCatalogEntry:
    if image_profile:
        entry = find_image_profile(image_profile, provider=provider)
        if entry is None:
            raise ValueError(f"Unknown image profile '{image_profile}' for provider '{provider}'.")
        return entry

    if requested_image:
        entry = find_image_by_name(requested_image, provider=provider)
        if entry is None:
            raise ValueError(
                f"Image '{requested_image}' is not in the trusted Sheshnaag catalog for provider '{provider}'."
            )
        return entry

    default_profile = default_image_profile(provider=provider, collectors=collectors)
    entry = find_image_profile(default_profile, provider=provider)
    if entry is None:
        raise ValueError(f"No trusted image profile '{default_profile}' for provider '{provider}'.")
    return entry
