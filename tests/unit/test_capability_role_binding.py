"""V5 W0c — capability role binding tests.

Verifies the data shape (``Capability.requester_roles`` populated per
the V5 plan tier) and the
:meth:`CapabilityPolicy.permitted_requester_for` helper. Does NOT touch
the V4 issue() flow — that wiring is V6.
"""

from __future__ import annotations

import pytest

from app.services.capability_policy import (
    CAPABILITIES,
    CapabilityPolicy,
)


SENIOR_PLUS_CAPS = {
    "external_disclosure",
    "specimen_exfil",
    "destructive_defang",
    "red_team_emulation",
    "offensive_research",
    "network_egress_open",
    "kernel_driver_load",
}

ANALYST_PLUS_CAPS = {
    "dynamic_detonation",
    "cloud_ai_provider_use",
    "autonomous_agent_run",
    "exploit_validation",
    "memory_exfil_to_host",
}


def test_every_v5_capability_has_requester_roles_set():
    """All 12 V4-era capabilities must have a non-None requester_roles."""
    expected = SENIOR_PLUS_CAPS | ANALYST_PLUS_CAPS
    assert set(CAPABILITIES) == expected, (
        f"capability set drifted: {set(CAPABILITIES) ^ expected}"
    )
    for name, cap in CAPABILITIES.items():
        assert cap.requester_roles is not None, (
            f"{name} must have explicit requester_roles in V5"
        )


def test_senior_plus_capabilities_lock_out_analyst():
    for name in SENIOR_PLUS_CAPS:
        cap = CAPABILITIES[name]
        assert cap.requester_roles == frozenset({"senior_analyst", "lab_lead"}), (
            f"{name} requester_roles drift: {cap.requester_roles}"
        )


def test_analyst_plus_capabilities_admit_analyst():
    for name in ANALYST_PLUS_CAPS:
        cap = CAPABILITIES[name]
        assert cap.requester_roles == frozenset(
            {"analyst", "senior_analyst", "lab_lead"}
        ), f"{name} requester_roles drift: {cap.requester_roles}"


def test_lab_lead_can_request_every_capability():
    for name in CAPABILITIES:
        assert CapabilityPolicy.permitted_requester_for(name, ["lab_lead"]) is True


def test_read_only_can_request_no_capability():
    for name in CAPABILITIES:
        assert (
            CapabilityPolicy.permitted_requester_for(name, ["read_only"]) is False
        ), f"read_only must not be a permitted requester for {name}"


def test_analyst_blocked_from_senior_plus_capabilities():
    for name in SENIOR_PLUS_CAPS:
        assert (
            CapabilityPolicy.permitted_requester_for(name, ["analyst"]) is False
        ), f"analyst must not request senior+ capability {name}"


def test_unknown_capability_is_fail_closed():
    assert (
        CapabilityPolicy.permitted_requester_for("not_a_capability", ["lab_lead"])
        is False
    )


def test_empty_roles_denies():
    for name in CAPABILITIES:
        assert (
            CapabilityPolicy.permitted_requester_for(name, []) is False
        ), f"empty roles must not pass for {name}"


def test_helper_accepts_any_iterable():
    # tuple
    assert CapabilityPolicy.permitted_requester_for(
        "dynamic_detonation", ("analyst",)
    ) is True
    # set
    assert CapabilityPolicy.permitted_requester_for(
        "dynamic_detonation", {"analyst"}
    ) is True
    # generator
    assert CapabilityPolicy.permitted_requester_for(
        "dynamic_detonation", (r for r in ["analyst"])
    ) is True
