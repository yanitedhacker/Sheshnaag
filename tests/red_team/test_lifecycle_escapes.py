"""V5 kill-criteria item 4: lifecycle red-team test.

Enumerates every (role × from_state × to_state) combination. For each
combination, asserts:
  * If the (from_state, to_state) edge does not exist in TRANSITIONS,
    the service raises IllegalTransitionError (regardless of role).
  * If the edge exists and the role is in allowed_roles, the transition
    succeeds.
  * If the edge exists but the role is *not* in allowed_roles, the
    service raises RoleNotPermittedError.

This is the gate test — no transition can be made by a role without
permission. Any escape is a V5 ship-blocker.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.core.database import Base
from app.models.malware_lab import AnalysisCase
from app.models.v2 import Tenant
from app.services.case_workflow import (
    TRANSITIONS,
    CaseLifecycleState,
    CaseWorkflowService,
    IllegalTransitionError,
    RoleNotPermittedError,
)

V5_ROLES = ("analyst", "senior_analyst", "reviewer", "lab_lead", "read_only")
ALL_STATES = tuple(CaseLifecycleState)


def _setup():
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
    return sess


def _fresh_case(sess, state: CaseLifecycleState) -> int:
    case = AnalysisCase(
        tenant_id=1,
        title="rt",
        analyst_name="rt",
        status="open",
        lifecycle_state=state.value,
    )
    sess.add(case)
    sess.flush()
    return case.id


def _legal_edges() -> dict[tuple[CaseLifecycleState, CaseLifecycleState], frozenset[str]]:
    return {(r.from_state, r.to_state): r.allowed_roles for r in TRANSITIONS}


@pytest.mark.parametrize("role", V5_ROLES)
@pytest.mark.parametrize("from_state", ALL_STATES)
@pytest.mark.parametrize("to_state", ALL_STATES)
def test_every_role_state_combination(role, from_state, to_state):
    if from_state == to_state:
        # Self-edge: never legal in our table; expect IllegalTransitionError.
        edges = _legal_edges()
        assert (from_state, to_state) not in edges, (
            f"self-edges should not exist in TRANSITIONS: {from_state}"
        )

    sess = _setup()
    cid = _fresh_case(sess, from_state)
    svc = CaseWorkflowService(sess)

    edges = _legal_edges()
    rule_allowed_roles = edges.get((from_state, to_state))

    if rule_allowed_roles is None:
        # No rule for this edge — every role must be denied with
        # IllegalTransitionError.
        with pytest.raises(IllegalTransitionError):
            svc.transition(
                case_id=cid,
                to_state=to_state,
                actor="actor",
                actor_roles=[role],
            )
    elif role in rule_allowed_roles:
        # Legal edge + permitted role — succeeds.
        audit = svc.transition(
            case_id=cid,
            to_state=to_state,
            actor="actor",
            actor_roles=[role],
        )
        assert audit.from_state == from_state.value
        assert audit.to_state == to_state.value
    else:
        # Legal edge but role not in allowed_roles — must reject.
        with pytest.raises(RoleNotPermittedError):
            svc.transition(
                case_id=cid,
                to_state=to_state,
                actor="actor",
                actor_roles=[role],
            )

    sess.close()


def test_no_role_can_skip_review():
    """No combination of roles bypasses review on the way to shipped.

    A case in TRIAGE or ANALYSIS or REVIEW must transit through REVIEW
    and READY_TO_SHIP before SHIPPED. The transition table does not
    contain a direct edge to SHIPPED from anywhere except READY_TO_SHIP.
    """
    edges_into_shipped = [r for r in TRANSITIONS if r.to_state == CaseLifecycleState.SHIPPED]
    sources = {r.from_state for r in edges_into_shipped}
    assert sources == {CaseLifecycleState.READY_TO_SHIP}, (
        f"unexpected SHIPPED predecessors: {sources}"
    )


def test_archive_terminal_for_non_lab_lead():
    """Only lab_lead can re-open an archived case.

    Defensive check: if any other role gains an `archived -> *` rule,
    this test trips so we re-evaluate the safety story.
    """
    archived_outbound = [r for r in TRANSITIONS if r.from_state == CaseLifecycleState.ARCHIVED]
    for rule in archived_outbound:
        assert rule.allowed_roles == frozenset({"lab_lead"}), (
            f"{rule.from_state.value} -> {rule.to_state.value} "
            f"allows {rule.allowed_roles}, expected only lab_lead"
        )


def test_read_only_has_no_transition_authority():
    """The read_only role must not appear in any rule's allowed_roles."""
    for rule in TRANSITIONS:
        assert "read_only" not in rule.allowed_roles, f"read_only must not transition: {rule}"
