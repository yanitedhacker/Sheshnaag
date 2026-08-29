"""Tests for pending exact-action authorization request persistence."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.time import utc_now
from app.models.capability import (
    AuditLogEntry,
    AuthorizationArtifact,
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
)
from app.services.capability_policy import (
    AuthorizationWorkflowError,
    CapabilityPolicy,
    HmacDevSigner,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    AuthorizationArtifact.__table__.create(engine)
    AuditLogEntry.__table__.create(engine)
    AuthorizationRequestRecord.__table__.create(engine)
    AuthorizationDecisionRecord.__table__.create(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


@pytest.fixture()
def policy(session):
    return CapabilityPolicy(
        session,
        signer=HmacDevSigner(key=b"authorization-workflow-test-key"),
    )


def _pending_request(**overrides):
    values = {
        "request_id": "areq_0123456789abcdef",
        "capability": "autonomous_agent_run",
        "scope": {
            "tenant_id": 7,
            "action": "autonomous_agent_run",
            "action_digest": "sha256:" + "a" * 64,
        },
        "action": "autonomous_agent_run",
        "action_digest": "sha256:" + "a" * 64,
        "requester": "analyst@example.com",
        "reason": "Review one exact read-only agent action.",
        "requested_ttl_seconds": 3600,
        "status": "pending",
        "required_approvals": 1,
        "requires_admin_approval": False,
        "created_at": utc_now(),
        "expires_at": utc_now() + timedelta(hours=1),
    }
    values.update(overrides)
    return AuthorizationRequestRecord(**values)


def test_one_reviewer_cannot_create_two_decisions_for_one_request(session):
    request = _pending_request()
    session.add(request)
    session.flush()
    session.add(
        AuthorizationDecisionRecord(
            request_id=request.request_id,
            reviewer="reviewer@example.com",
            reviewer_roles=["reviewer"],
            decision="approve",
            note="Scope verified.",
        )
    )
    session.flush()

    session.add(
        AuthorizationDecisionRecord(
            request_id=request.request_id,
            reviewer="reviewer@example.com",
            reviewer_roles=["reviewer"],
            decision="reject",
            note="A second decision must not replace the first.",
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize("invalid_status", ["", "approved", "complete"])
def test_request_status_rejects_unknown_values(session, invalid_status):
    session.add(_pending_request(status=invalid_status))

    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize("invalid_decision", ["", "allow", "deny"])
def test_decision_rejects_unknown_values(session, invalid_decision):
    request = _pending_request()
    session.add(request)
    session.flush()
    session.add(
        AuthorizationDecisionRecord(
            request_id=request.request_id,
            reviewer="reviewer@example.com",
            reviewer_roles=["reviewer"],
            decision=invalid_decision,
            note=None,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def _create_request(policy, capability="autonomous_agent_run"):
    return policy.create_request(
        capability=capability,
        action=capability,
        arguments={
            "tenant_id": 7,
            "case_id": 42,
            "goal": "Review this exact case.",
            "max_steps": 3,
        },
        requester="analyst@example.com",
        reason="Independent approval test.",
        requested_ttl=timedelta(hours=1),
    )


def test_create_request_is_pending_and_writes_request_audit(policy, session):
    request = _create_request(policy)

    assert request.status == "pending"
    assert request.artifact_id is None
    assert request.required_approvals == 1
    assert request.requires_admin_approval is False
    assert request.scope == {
        "tenant_id": 7,
        "case_id": 42,
        "action": "autonomous_agent_run",
        "action_digest": request.action_digest,
    }
    audit = session.query(AuditLogEntry).one()
    assert audit.action == "request"
    assert audit.actor == "analyst@example.com"
    assert audit.payload["request_id"] == request.request_id


def test_requester_cannot_decide_their_own_request(policy, session):
    request = _create_request(policy)

    with pytest.raises(AuthorizationWorkflowError, match="requester_cannot_review"):
        policy.record_decision(
            request.request_id,
            reviewer="analyst@example.com",
            reviewer_roles=["senior_analyst"],
            decision="approve",
            note="Self approval must fail.",
        )

    assert session.query(AuthorizationDecisionRecord).count() == 0
    assert session.query(AuthorizationArtifact).count() == 0


def test_one_reviewer_cannot_decide_twice(policy, session):
    request = _create_request(policy, capability="destructive_defang")
    first = policy.record_decision(
        request.request_id,
        reviewer="reviewer@example.com",
        reviewer_roles=["reviewer"],
        decision="approve",
        note="First review.",
    )
    assert first.artifact is None

    with pytest.raises(AuthorizationWorkflowError, match="duplicate_reviewer_decision"):
        policy.record_decision(
            request.request_id,
            reviewer="reviewer@example.com",
            reviewer_roles=["reviewer"],
            decision="reject",
            note="Second decision must fail.",
        )

    assert session.query(AuthorizationDecisionRecord).count() == 1


def test_rejection_resolves_request_without_artifact(policy, session):
    request = _create_request(policy)

    result = policy.record_decision(
        request.request_id,
        reviewer="reviewer@example.com",
        reviewer_roles=["reviewer"],
        decision="reject",
        note="The scope is too broad.",
    )

    assert result.request.status == "rejected"
    assert result.artifact is None
    assert result.request.resolved_at is not None
    assert session.query(AuthorizationArtifact).count() == 0


def test_single_independent_approval_issues_bound_artifact(policy, session):
    request = _create_request(policy)

    result = policy.record_decision(
        request.request_id,
        reviewer="reviewer@example.com",
        reviewer_roles=["reviewer"],
        decision="approve",
        note="Exact action verified.",
    )

    assert result.request.status == "issued"
    assert result.artifact is not None
    assert result.request.artifact_id == result.artifact.artifact_id
    assert result.artifact.scope == request.scope
    assert result.artifact.scope["action_digest"] == request.action_digest
    audit_actions = [
        row.action
        for row in session.query(AuditLogEntry).order_by(AuditLogEntry.idx.asc()).all()
    ]
    assert audit_actions == ["request", "approve", "issue"]


def test_dual_review_waits_for_two_distinct_approvals(policy):
    request = _create_request(policy, capability="destructive_defang")

    first = policy.record_decision(
        request.request_id,
        reviewer="reviewer-one@example.com",
        reviewer_roles=["reviewer"],
        decision="approve",
        note=None,
    )
    assert first.request.status == "pending"
    assert first.artifact is None

    second = policy.record_decision(
        request.request_id,
        reviewer="reviewer-two@example.com",
        reviewer_roles=["senior_analyst"],
        decision="approve",
        note=None,
    )

    assert second.request.status == "issued"
    assert second.artifact is not None


def test_dual_plus_admin_waits_for_lab_lead_approval(policy):
    request = _create_request(policy, capability="network_egress_open")

    first = policy.record_decision(
        request.request_id,
        reviewer="reviewer-one@example.com",
        reviewer_roles=["reviewer"],
        decision="approve",
        note=None,
    )
    second = policy.record_decision(
        request.request_id,
        reviewer="reviewer-two@example.com",
        reviewer_roles=["senior_analyst"],
        decision="approve",
        note=None,
    )
    assert first.artifact is None
    assert second.artifact is None
    assert second.request.status == "pending"

    third = policy.record_decision(
        request.request_id,
        reviewer="lead@example.com",
        reviewer_roles=["lab_lead"],
        decision="approve",
        note="Administrative scope approved.",
    )

    assert third.request.status == "issued"
    assert third.artifact is not None
