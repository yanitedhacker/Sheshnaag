"""V6 W4 — purple team ATT&CK coverage gate."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.database import Base
from app.services.capability_policy import CapabilityPolicy, IssuanceRequest, Reviewer
from app.services.purple_team_service import PurpleTeamService


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    CapabilityPolicy(session).issue(
        IssuanceRequest(
            capability="red_team_emulation",
            scope={"tenant": "demo"},
            requester="purple@example.com",
            reason="gate",
            requester_roles=["senior_analyst"],
        ),
        reviewers=[Reviewer("a", "approve"), Reviewer("b", "approve")],
    )
    session.commit()
    return session


@pytest.mark.unit
def test_purple_team_meets_80_technique_gate():
    session = _session()
    result = PurpleTeamService(session).run_replay(
        actor="purple@example.com",
        scope={"tenant": "demo"},
    )
    gap = result["coverage_gap"]
    assert gap["meets_gate_80"] is True
    assert gap["techniques_executed"] >= 80
