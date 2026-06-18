"""V6 W1 — requester role enforcement in issue()."""

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


@pytest.mark.unit
def test_issue_denies_analyst_for_offensive_research():
    session = _session()
    policy = CapabilityPolicy(session)
    with pytest.raises(ValueError, match="requester_role_denied"):
        policy.issue(
            IssuanceRequest(
                capability="offensive_research",
                scope={"tenant": "demo"},
                requester="analyst@example.com",
                reason="test",
                engagement_ref="sha256:abc",
                is_admin_approved=True,
                requester_roles=["analyst"],
            ),
            reviewers=[
                Reviewer("r1", "approve"),
                Reviewer("r2", "approve"),
            ],
        )


@pytest.mark.unit
def test_issue_allows_senior_analyst_for_red_team():
    session = _session()
    policy = CapabilityPolicy(session)
    artifact = policy.issue(
        IssuanceRequest(
            capability="red_team_emulation",
            scope={"tenant": "demo"},
            requester="senior@example.com",
            reason="test",
            requester_roles=["senior_analyst"],
        ),
        reviewers=[Reviewer("r1", "approve"), Reviewer("r2", "approve")],
    )
    assert artifact.capability == "red_team_emulation"
