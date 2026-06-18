"""V6+ adversary harness — capability policy escape attempts."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.database import Base
from app.services.capability_policy import CapabilityPolicy, IssuanceRequest, Reviewer


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)()


@pytest.mark.red_team
def test_analyst_cannot_issue_offensive_research():
    session = _session()
    policy = CapabilityPolicy(session)
    with pytest.raises(ValueError, match="requester_role_denied"):
        policy.issue(
            IssuanceRequest(
                capability="offensive_research",
                scope={"target": "unauthorized.example"},
                requester="evil-analyst",
                reason="escape attempt",
                engagement_ref="doc",
                is_admin_approved=True,
                requester_roles=["analyst"],
            ),
            reviewers=[Reviewer("r1", "approve"), Reviewer("r2", "approve")],
        )


@pytest.mark.red_team
def test_single_reviewer_cannot_issue_dual_capability():
    session = _session()
    policy = CapabilityPolicy(session)
    with pytest.raises(ValueError, match="need_2_approvals"):
        policy.issue(
            IssuanceRequest(
                capability="exploit_validation",
                scope={},
                requester="senior@example.com",
                reason="single reviewer escape",
                requester_roles=["senior_analyst"],
            ),
            reviewers=[Reviewer("solo", "approve")],
        )


@pytest.mark.red_team
def test_requester_cannot_self_approve():
    session = _session()
    policy = CapabilityPolicy(session)
    with pytest.raises(ValueError, match="requester_cannot_review"):
        policy.issue(
            IssuanceRequest(
                capability="dynamic_detonation",
                scope={},
                requester="self@example.com",
                reason="self approve",
                requester_roles=["analyst"],
            ),
            reviewers=[Reviewer("self@example.com", "approve")],
        )
