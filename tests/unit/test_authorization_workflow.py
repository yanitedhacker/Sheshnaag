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
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    AuthorizationRequestRecord.__table__.create(engine)
    AuthorizationDecisionRecord.__table__.create(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


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
