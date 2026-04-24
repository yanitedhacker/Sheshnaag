"""Unit tests for the V4 capability policy engine."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401  # register all model tables
from app.models.capability import AuthorizationArtifact, AuditLogEntry
from app.services.capability_policy import (
    CAPABILITIES,
    CapabilityPolicy,
    HmacDevSigner,
    IssuanceRequest,
    Reviewer,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Create only the two capability-policy tables to avoid FK cascades into
    # unrelated models that require a richer schema.
    AuthorizationArtifact.__table__.create(engine)
    AuditLogEntry.__table__.create(engine)

    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


@pytest.fixture()
def policy(session):
    return CapabilityPolicy(session, signer=HmacDevSigner(key=b"unit-test-key"))


def _issue(policy, capability, *, requester="alice@example.com", reviewers=None,
           scope=None, engagement_ref=None, is_admin_approved=False, ttl=None):
    cap = CAPABILITIES[capability]
    if reviewers is None:
        if cap.review_kind == "single":
            reviewers = [Reviewer("bob@example.com", "approve")]
        else:
            reviewers = [
                Reviewer("bob@example.com", "approve"),
                Reviewer("carol@example.com", "approve"),
            ]
    request = IssuanceRequest(
        capability=capability,
        scope=scope or {"tenant_id": 1},
        requester=requester,
        reason="test",
        engagement_ref=engagement_ref or (
            "sha256=" + "0" * 64 if cap.requires_engagement_doc else None
        ),
        is_admin_approved=is_admin_approved or cap.review_kind == "dual_plus_admin",
        requested_ttl=ttl,
    )
    return policy.issue(request, reviewers)


def test_denies_without_artifact(policy):
    decision = policy.evaluate(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        actor="alice@example.com",
    )
    assert decision.permitted is False
    assert decision.reason == "no_active_artifact"
    assert decision.artifact_id is None


def test_permits_with_valid_artifact(policy):
    artifact = _issue(policy, "dynamic_detonation")
    decision = policy.evaluate(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        actor="alice@example.com",
    )
    assert decision.permitted is True
    assert decision.artifact_id == artifact.artifact_id
    assert decision.reason == "artifact_match"


def test_denies_expired_artifact(policy, session):
    artifact = _issue(policy, "dynamic_detonation")
    # Shove the expiry into the past directly.
    artifact.expires_at = artifact.issued_at - timedelta(seconds=1)
    session.flush()

    decision = policy.evaluate(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        actor="alice@example.com",
    )
    assert decision.permitted is False
    assert decision.reason == "no_active_artifact"


def test_denies_revoked_artifact(policy):
    artifact = _issue(policy, "dynamic_detonation")
    policy.revoke(artifact.artifact_id, actor="bob@example.com", reason="test-revoke")

    decision = policy.evaluate(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        actor="alice@example.com",
    )
    assert decision.permitted is False


def test_denies_self_review(policy):
    with pytest.raises(ValueError, match="requester_cannot_review"):
        policy.issue(
            IssuanceRequest(
                capability="dynamic_detonation",
                scope={"tenant_id": 1},
                requester="alice@example.com",
                reason="self-review",
            ),
            [Reviewer("alice@example.com", "approve")],
        )


def test_enforces_dual_review(policy):
    # external_disclosure is dual_plus_admin
    with pytest.raises(ValueError, match="need_2_approvals"):
        policy.issue(
            IssuanceRequest(
                capability="external_disclosure",
                scope={"tenant_id": 1},
                requester="alice@example.com",
                reason="single-reviewer",
                is_admin_approved=True,
            ),
            [Reviewer("bob@example.com", "approve")],
        )

    # Two approvals without admin should also fail for dual_plus_admin
    with pytest.raises(ValueError, match="need_admin_approval"):
        policy.issue(
            IssuanceRequest(
                capability="external_disclosure",
                scope={"tenant_id": 1},
                requester="alice@example.com",
                reason="no-admin",
                is_admin_approved=False,
            ),
            [
                Reviewer("bob@example.com", "approve"),
                Reviewer("carol@example.com", "approve"),
            ],
        )


def test_ttl_clamped_to_max(policy):
    # offensive_research has max 7 days.
    artifact = _issue(
        policy,
        "offensive_research",
        ttl=timedelta(days=99),
        engagement_ref="sha256=" + "a" * 64,
    )
    delta = artifact.expires_at - artifact.issued_at
    max_ttl = CAPABILITIES["offensive_research"].max_ttl
    # Should clamp to max_ttl exactly (within microseconds).
    assert abs(delta.total_seconds() - max_ttl.total_seconds()) < 1.0
