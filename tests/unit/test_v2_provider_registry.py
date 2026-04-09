"""Unit coverage for v2 provider and trusted image selection."""

import pytest

from app.lab.image_catalog import find_image_profile, resolve_catalog_entry
from app.lab.provider_registry import build_default_provider_registry


@pytest.mark.unit
def test_provider_registry_exposes_supported_v2_providers():
    registry = build_default_provider_registry()
    assert tuple(sorted(registry.supported())) == ("docker_kali", "lima")
    assert registry.create("docker_kali").provider_name == "docker_kali"
    assert registry.create("lima").provider_name == "lima"


@pytest.mark.unit
def test_image_catalog_resolves_tracee_profile_from_collectors():
    entry = resolve_catalog_entry(provider="docker_kali", collectors=["process_tree", "tracee_events"])
    assert entry.profile == "tracee_capable"
    assert entry.supports_tracee is True


@pytest.mark.unit
def test_lima_secure_profile_is_trusted():
    entry = find_image_profile("secure_lima", provider="lima")
    assert entry is not None
    assert entry.secure_mode_only is True


@pytest.mark.unit
def test_untrusted_image_is_rejected():
    with pytest.raises(ValueError, match="trusted Sheshnaag catalog"):
        resolve_catalog_entry(
            provider="docker_kali",
            requested_image="docker.io/library/alpine:latest",
            collectors=["process_tree"],
        )
