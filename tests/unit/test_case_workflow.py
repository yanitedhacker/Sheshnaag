"""Unit tests for V5 W0b CaseWorkflowService."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401  registers tables
from app.models.malware_lab import AnalysisCase, CaseStateTransition
from app.models.v2 import Tenant
from app.services.case_workflow import (
    CaseLifecycleState,
    CaseNotFoundError,
    CaseWorkflowService,
    IllegalTransitionError,
    RoleNotPermittedError,
    TRANSITIONS,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    sess.add(Tenant(id=1, slug="t1", name="T1"))
    sess.commit()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


def _new_case(session, *, state="triage") -> int:
    case = AnalysisCase(
        tenant_id=1,
        title="t",
        analyst_name="alice",
        status="open",
        lifecycle_state=state,
    )
    session.add(case)
    session.flush()
    return case.id


def test_happy_path_triage_to_analysis(session):
    cid = _new_case(session)
    svc = CaseWorkflowService(session)
    audit = svc.transition(
        case_id=cid,
        to_state=CaseLifecycleState.ANALYSIS,
        actor="alice@x",
        actor_roles=["analyst"],
    )
    assert audit.from_state == "triage"
    assert audit.to_state == "analysis"
    assert audit.role_at_transition == "analyst"
    assert audit.actor == "alice@x"
    case = session.query(AnalysisCase).filter_by(id=cid).first()
    assert case.lifecycle_state == "analysis"
    assert case.state_changed_by == "alice@x"


def test_full_forward_path(session):
    cid = _new_case(session)
    svc = CaseWorkflowService(session)
    svc.transition(case_id=cid, to_state=CaseLifecycleState.ANALYSIS, actor="a", actor_roles=["analyst"])
    svc.transition(case_id=cid, to_state=CaseLifecycleState.REVIEW, actor="a", actor_roles=["analyst"])
    svc.transition(case_id=cid, to_state=CaseLifecycleState.READY_TO_SHIP, actor="r", actor_roles=["reviewer"])
    svc.transition(case_id=cid, to_state=CaseLifecycleState.SHIPPED, actor="s", actor_roles=["senior_analyst"])
    svc.transition(case_id=cid, to_state=CaseLifecycleState.ARCHIVED, actor="ll", actor_roles=["lab_lead"])

    case = session.query(AnalysisCase).filter_by(id=cid).first()
    assert case.lifecycle_state == "archived"

    audits = (
        session.query(CaseStateTransition)
        .filter_by(case_id=cid)
        .order_by(CaseStateTransition.id)
        .all()
    )
    assert [(a.from_state, a.to_state) for a in audits] == [
        ("triage", "analysis"),
        ("analysis", "review"),
        ("review", "ready_to_ship"),
        ("ready_to_ship", "shipped"),
        ("shipped", "archived"),
    ]


def test_illegal_transition_raises(session):
    cid = _new_case(session, state="triage")
    svc = CaseWorkflowService(session)
    with pytest.raises(IllegalTransitionError):
        # triage cannot jump straight to shipped
        svc.transition(
            case_id=cid,
            to_state=CaseLifecycleState.SHIPPED,
            actor="ll",
            actor_roles=["lab_lead"],
        )


def test_role_not_permitted_raises(session):
    cid = _new_case(session, state="ready_to_ship")
    svc = CaseWorkflowService(session)
    # analyst cannot ship
    with pytest.raises(RoleNotPermittedError):
        svc.transition(
            case_id=cid,
            to_state=CaseLifecycleState.SHIPPED,
            actor="x",
            actor_roles=["analyst"],
        )


def test_case_not_found(session):
    svc = CaseWorkflowService(session)
    with pytest.raises(CaseNotFoundError):
        svc.transition(
            case_id=999,
            to_state=CaseLifecycleState.ANALYSIS,
            actor="x",
            actor_roles=["analyst"],
        )


def test_legal_transitions_for_state(session):
    svc = CaseWorkflowService(session)
    out = svc.legal_transitions_for_state(CaseLifecycleState.REVIEW)
    assert set(out) == {
        CaseLifecycleState.ANALYSIS,
        CaseLifecycleState.READY_TO_SHIP,
        CaseLifecycleState.ARCHIVED,
    }


def test_legal_transitions_for_role(session):
    svc = CaseWorkflowService(session)
    # analyst can't move REVIEW (only reviewer/lab_lead can)
    assert svc.legal_transitions_for_role(CaseLifecycleState.REVIEW, "analyst") == []
    # reviewer can move REVIEW to 3 places
    assert set(svc.legal_transitions_for_role(CaseLifecycleState.REVIEW, "reviewer")) == {
        CaseLifecycleState.ANALYSIS,
        CaseLifecycleState.READY_TO_SHIP,
        CaseLifecycleState.ARCHIVED,
    }


def test_transition_table_invariants():
    # No duplicate (from, to) edges.
    seen = set()
    for r in TRANSITIONS:
        key = (r.from_state, r.to_state)
        assert key not in seen, f"duplicate rule: {key}"
        seen.add(key)
    # All states reachable from triage (the start state).
    forward = {CaseLifecycleState.TRIAGE}
    changed = True
    while changed:
        changed = False
        for r in TRANSITIONS:
            if r.from_state in forward and r.to_state not in forward:
                forward.add(r.to_state)
                changed = True
    assert forward == set(CaseLifecycleState), (
        f"unreachable states: {set(CaseLifecycleState) - forward}"
    )
