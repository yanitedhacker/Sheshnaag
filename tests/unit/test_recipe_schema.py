"""Unit tests for app.lab.recipe_schema validation, linting, diffing, and sign-off policy."""

from __future__ import annotations

import pytest

from app.lab.recipe_schema import (
    KNOWN_COLLECTORS,
    RecipeDiffEngine,
    RecipeLinter,
    RecipeSchemaValidator,
    SignOffPolicy,
)


def _valid_recipe(**overrides):
    """Minimal recipe that passes schema and typical lint rules."""
    base = {
        "base_image": "kalilinux/kali-rolling:2026.1",
        "command": ["bash", "-lc", "echo test"],
        "network_policy": {"allow_egress_hosts": []},
        "collectors": [
            "process_tree",
            "package_inventory",
            "file_diff",
            "network_metadata",
            "service_logs",
            "tracee_events",
        ],
        "teardown_policy": {"mode": "destroy_immediately", "ephemeral_workspace": True},
        "risk_level": "standard",
        "requires_acknowledgement": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_valid_recipe_passes_schema():
    v = RecipeSchemaValidator()
    result = v.validate(_valid_recipe())
    assert result.valid is True
    assert result.errors == []


@pytest.mark.unit
def test_missing_base_image_fails():
    content = _valid_recipe()
    del content["base_image"]
    result = RecipeSchemaValidator().validate(content)
    assert result.valid is False
    assert any("base_image" in e for e in result.errors)


@pytest.mark.unit
def test_empty_command_fails():
    result = RecipeSchemaValidator().validate(_valid_recipe(command=[]))
    assert result.valid is False
    assert any("command" in e.lower() for e in result.errors)


@pytest.mark.unit
def test_missing_network_policy_fails():
    content = _valid_recipe()
    del content["network_policy"]
    result = RecipeSchemaValidator().validate(content)
    assert result.valid is False
    assert any("network_policy" in e for e in result.errors)


@pytest.mark.unit
def test_invalid_teardown_mode_fails():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(teardown_policy={"mode": "destroy_container", "ephemeral_workspace": True})
    )
    assert result.valid is False
    assert any("destroy_container" in e or "teardown_policy.mode" in e for e in result.errors)


@pytest.mark.unit
def test_invalid_risk_level_fails():
    result = RecipeSchemaValidator().validate(_valid_recipe(risk_level="low"))
    assert result.valid is False
    assert any("risk_level" in e for e in result.errors)


@pytest.mark.unit
def test_sensitive_requires_acknowledgement():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(risk_level="sensitive", requires_acknowledgement=False)
    )
    assert result.valid is False
    assert any("requires_acknowledgement" in e for e in result.errors)


@pytest.mark.unit
def test_high_requires_acknowledgement():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(risk_level="high", requires_acknowledgement=False)
    )
    assert result.valid is False
    assert any("requires_acknowledgement" in e for e in result.errors)


@pytest.mark.unit
def test_standard_no_acknowledgement_ok():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(risk_level="standard", requires_acknowledgement=False)
    )
    assert result.valid is True
    assert result.errors == []


@pytest.mark.unit
def test_unknown_collector_fails():
    coll = list(KNOWN_COLLECTORS)
    coll.append("magic_unicorn")
    result = RecipeSchemaValidator().validate(_valid_recipe(collectors=coll))
    assert result.valid is False
    assert any("magic_unicorn" in e for e in result.errors)


@pytest.mark.unit
def test_mount_missing_source_fails():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(
            mounts=[
                {"target": "/workspace"},
            ]
        )
    )
    assert result.valid is False
    assert any("source" in e for e in result.errors)


@pytest.mark.unit
def test_invalid_workspace_retention_fails():
    result = RecipeSchemaValidator().validate(
        _valid_recipe(workspace_retention="invalid_retention_mode")
    )
    assert result.valid is False
    assert any("workspace_retention" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Lint
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_lint_clean_recipe():
    result = RecipeLinter().lint(_valid_recipe())
    assert result.errors == []
    assert result.has_blocking_errors is False


@pytest.mark.unit
def test_lint_dangerous_capability_warning():
    content = _valid_recipe(cap_add=["SYS_ADMIN"])
    result = RecipeLinter().lint(content)
    assert result.has_blocking_errors is False
    assert any("SYS_ADMIN" in w or "Risky capability" in w for w in result.warnings)


@pytest.mark.unit
def test_lint_egress_without_network_collector():
    content = _valid_recipe(
        network_policy={"allow_egress_hosts": ["example.com"]},
        collectors=[
            "process_tree",
            "package_inventory",
            "file_diff",
            "service_logs",
            "tracee_events",
        ],
    )
    result = RecipeLinter().lint(content)
    assert any("network_metadata" in w for w in result.warnings)


@pytest.mark.unit
def test_lint_high_risk_no_readonly_mounts():
    content = _valid_recipe(
        risk_level="high",
        requires_acknowledgement=True,
        mounts=[{"source": "/tmp", "target": "/data", "read_only": False}],
    )
    result = RecipeLinter().lint(content)
    assert any("read_only" in w.lower() or "read_only=True" in w for w in result.warnings)


@pytest.mark.unit
def test_lint_distro_mismatch_warning():
    content = _valid_recipe(base_image="ubuntu:24.04")
    result = RecipeLinter(expected_distro="kali").lint(content)
    assert any("mismatch" in w.lower() or "Kali" in w for w in result.warnings)


@pytest.mark.unit
def test_lint_missing_image_error():
    content = _valid_recipe()
    del content["base_image"]
    result = RecipeLinter().lint(content)
    assert result.has_blocking_errors is True
    assert any("base image" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_diff_no_changes():
    content = _valid_recipe()
    d = RecipeDiffEngine().diff(content, dict(content))
    assert d.changes == []
    assert d.policy_changes == []
    assert d.risk_level_changed is False
    assert d.collector_changes is False
    assert d.network_changes is False


@pytest.mark.unit
def test_diff_risk_level_change():
    old = _valid_recipe(risk_level="standard", requires_acknowledgement=False)
    new = _valid_recipe(risk_level="high", requires_acknowledgement=True)
    d = RecipeDiffEngine().diff(old, new)
    assert d.risk_level_changed is True
    assert any(c["field"] == "risk_level" for c in d.changes)


@pytest.mark.unit
def test_diff_collector_change():
    old = _valid_recipe()
    new = _valid_recipe(collectors=list(KNOWN_COLLECTORS)[:-1])
    d = RecipeDiffEngine().diff(old, new)
    assert d.collector_changes is True


@pytest.mark.unit
def test_diff_network_change():
    old = _valid_recipe(network_policy={"allow_egress_hosts": []})
    new = _valid_recipe(network_policy={"allow_egress_hosts": ["api.example.com"]})
    d = RecipeDiffEngine().diff(old, new)
    assert d.network_changes is True
    assert any(c["field"].startswith("network_policy") for c in d.changes)


@pytest.mark.unit
def test_diff_human_readable_contains_summary():
    old = _valid_recipe()
    new = _valid_recipe(risk_level="high", requires_acknowledgement=True)
    d = RecipeDiffEngine().diff(old, new)
    assert "Recipe revision diff" in d.human_readable
    assert "### Summary" in d.human_readable


@pytest.mark.unit
def test_diff_policy_relevant_flagged():
    old = _valid_recipe(risk_level="standard", requires_acknowledgement=False)
    new = _valid_recipe(risk_level="high", requires_acknowledgement=True)
    d = RecipeDiffEngine().diff(old, new)
    risk_changes = [c for c in d.changes if c["field"] == "risk_level"]
    assert risk_changes
    assert all(c.get("is_policy_relevant") is True for c in risk_changes)


# ---------------------------------------------------------------------------
# Sign-off
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_signoff_standard_one_approval():
    req = SignOffPolicy().evaluate("standard", capabilities=[])
    assert req.required_approvals == 1


@pytest.mark.unit
def test_signoff_high_two_approvals():
    req = SignOffPolicy().evaluate("high", capabilities=[])
    assert req.required_approvals == 2


@pytest.mark.unit
def test_signoff_restricted_cap_extra_approval():
    req = SignOffPolicy().evaluate("standard", capabilities=["SYS_ADMIN"])
    assert req.required_approvals == 2
    assert "SYS_ADMIN" in req.restricted_caps_present


@pytest.mark.unit
def test_signoff_high_eligible_roles():
    req = SignOffPolicy().evaluate("high", capabilities=[])
    assert set(req.eligible_roles) == {"lead", "security"}


@pytest.mark.unit
def test_signoff_standard_eligible_roles():
    req = SignOffPolicy().evaluate("standard", capabilities=[])
    assert set(req.eligible_roles) == {"lead", "security", "researcher"}


@pytest.mark.unit
def test_signoff_acknowledgement_text_contains_risk():
    req = SignOffPolicy().evaluate("sensitive", capabilities=[])
    assert "sensitive" in req.acknowledgement_text


@pytest.mark.unit
def test_register_acknowledgement():
    policy = SignOffPolicy()
    rec = policy.register_acknowledgement("alice", "I acknowledge the recipe risks.")
    assert rec.party == "alice"
    assert rec.acknowledgement_text == "I acknowledge the recipe risks."
    assert rec.acknowledged_at.endswith("Z") or "T" in rec.acknowledged_at
    assert policy.acknowledgements == [rec]
