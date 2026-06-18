"""Unit coverage for v2 provider and trusted image selection."""

from pathlib import Path

import pytest

from app.lab.docker_kali_provider import DockerKaliProvider
from app.lab.image_catalog import (
    KALI_ROLLING_MANIFEST_DIGEST,
    find_image_profile,
    resolve_catalog_entry,
)
from app.lab.provider_registry import build_default_provider_registry


@pytest.mark.unit
def test_provider_registry_exposes_supported_v2_providers():
    registry = build_default_provider_registry()
    assert tuple(sorted(registry.supported())) == ("docker_kali", "lima")
    assert registry.create("docker_kali").provider_name == "docker_kali"
    assert registry.create("lima").provider_name == "lima"


@pytest.mark.unit
def test_image_catalog_resolves_tracee_profile_from_collectors():
    entry = resolve_catalog_entry(
        provider="docker_kali", collectors=["process_tree", "tracee_events"]
    )
    assert entry.profile == "tracee_capable"
    assert entry.supports_tracee is True


@pytest.mark.unit
def test_baseline_image_is_bound_to_the_verified_kali_manifest():
    entry = resolve_catalog_entry(provider="docker_kali")

    assert entry.image == f"kalilinux/kali-rolling@{KALI_ROLLING_MANIFEST_DIGEST}"
    assert entry.digest == KALI_ROLLING_MANIFEST_DIGEST.removeprefix("sha256:")


@pytest.mark.unit
def test_docker_kali_uses_engine_default_confinement_without_fake_profile_paths():
    plan = DockerKaliProvider().build_plan(
        revision_content={"command": ["true"]},
        run_context={"tenant_slug": "test", "analyst_name": "test", "run_id": 1},
    )

    assert plan["security_options"] == ["no-new-privileges:true"]
    assert "--security-opt" in plan["docker_args"]
    assert "seccomp=default" not in plan["docker_args"]
    assert "apparmor=sheshnaag-default" not in plan["docker_args"]


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


@pytest.mark.unit
def test_osquery_image_explicitly_installs_collector_runtime_tools():
    root = Path(__file__).resolve().parents[2]
    dockerfile = (root / "lab/images/osquery/Dockerfile").read_text(encoding="utf-8")

    for package in ("bash", "coreutils", "findutils", "procps"):
        assert package in dockerfile
