"""Server-owned worker requirements for queued lab execution."""

from __future__ import annotations

from collections.abc import Collection

RISKY_ANALYSIS_MODES = frozenset(
    {"malware_detonation", "url_analysis", "email_analysis"}
)
SECURE_PROVIDER_NAMES = frozenset({"lima", "libvirt"})

STANDARD_WORKER_CAPABILITIES = frozenset({"docker"})
DETONATION_BASE_CAPABILITIES = frozenset({"pcap", "zeek", "secure-mode"})
LIBVIRT_DETONATION_CAPABILITIES = DETONATION_BASE_CAPABILITIES | frozenset(
    {"linux", "kvm", "libvirt"}
)
LIMA_DETONATION_CAPABILITIES = DETONATION_BASE_CAPABILITIES | frozenset({"lima"})


def normalize_capabilities(values: Collection[str]) -> frozenset[str]:
    """Return normalized, non-empty capability names."""

    return frozenset(str(value).strip().lower() for value in values if str(value).strip())


def required_worker_capabilities(
    *,
    provider: str,
    launch_mode: str,
    analysis_mode: str,
) -> frozenset[str]:
    """Derive worker requirements from the persisted run contract."""

    normalized_launch_mode = str(launch_mode or "").strip().lower()
    if normalized_launch_mode != "execute":
        return frozenset()

    normalized_provider = str(provider or "").strip().lower()
    normalized_analysis_mode = str(analysis_mode or "").strip().lower()
    if normalized_analysis_mode in RISKY_ANALYSIS_MODES:
        if normalized_provider == "libvirt":
            return LIBVIRT_DETONATION_CAPABILITIES
        if normalized_provider == "lima":
            return LIMA_DETONATION_CAPABILITIES
        raise ValueError(
            "Risky execute-mode analysis requires a secure provider: lima or libvirt."
        )

    return STANDARD_WORKER_CAPABILITIES

