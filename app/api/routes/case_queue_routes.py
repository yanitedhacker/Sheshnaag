"""V5 W2a — case lifecycle queue.

Distinct from the V4 ``/api/review-queue`` (which is run/evidence/
artifact-centric). This endpoint surfaces ``AnalysisCase`` rows
filtered by ``lifecycle_state``, alongside the legal next transitions
from the caller's role(s). Used by the ReviewQueuePage "Cases"
section.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.models.malware_lab import AnalysisCase, CaseStateTransition
from app.services.case_workflow import (
    CaseLifecycleState,
    CaseWorkflowService,
)

router = APIRouter(prefix="/api/v5/cases/queue", tags=["Sheshnaag V5 Case Queue"])


class CaseQueueItem(BaseModel):
    case_id: int
    title: str
    summary: str | None
    lifecycle_state: str
    state_changed_at: datetime | None
    state_changed_by: str | None
    priority: str
    analyst_name: str
    legal_transitions_for_caller: list[str]
    last_transition_actor: str | None


class CaseQueueResponse(BaseModel):
    count: int
    state_counts: dict[str, int]
    items: list[CaseQueueItem]


@router.get("", response_model=CaseQueueResponse)
def list_case_queue(
    lifecycle_state: str | None = Query(
        None,
        description=(
            "One of triage/analysis/review/ready_to_ship/shipped/archived. "
            "Omit to return all states."
        ),
    ),
    limit: int = Query(100, ge=1, le=500),
    token_data: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> CaseQueueResponse:
    if lifecycle_state is not None:
        try:
            lifecycle_enum = CaseLifecycleState(lifecycle_state)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"unknown_lifecycle_state:{lifecycle_state}",
            ) from e
    else:
        lifecycle_enum = None

    workflow = CaseWorkflowService(session)
    caller_roles = list(token_data.roles or [])

    query = session.query(AnalysisCase)
    if lifecycle_enum is not None:
        query = query.filter(AnalysisCase.lifecycle_state == lifecycle_enum.value)
    rows = query.order_by(AnalysisCase.state_changed_at.desc().nullslast()).limit(limit).all()

    # Lookup latest transition actor per case in one batch.
    case_ids = [row.id for row in rows]
    latest_actor: dict[int, str] = {}
    if case_ids:
        sub = (
            session.query(CaseStateTransition.case_id, CaseStateTransition.actor)
            .filter(CaseStateTransition.case_id.in_(case_ids))
            .order_by(
                CaseStateTransition.case_id,
                CaseStateTransition.id.desc(),
            )
            .all()
        )
        for case_id, actor in sub:
            latest_actor.setdefault(case_id, actor)

    items: list[CaseQueueItem] = []
    for row in rows:
        try:
            state_enum = CaseLifecycleState(row.lifecycle_state)
        except ValueError:
            # Defensive: row has a non-V5 state value somehow. Surface
            # the raw value but compute no transitions.
            transitions: list[str] = []
        else:
            transition_targets: set[str] = set()
            for caller_role in caller_roles:
                for target in workflow.legal_transitions_for_role(state_enum, caller_role):
                    transition_targets.add(target.value)
            transitions = sorted(transition_targets)

        items.append(
            CaseQueueItem(
                case_id=row.id,
                title=row.title,
                summary=row.summary,
                lifecycle_state=row.lifecycle_state,
                state_changed_at=row.state_changed_at,
                state_changed_by=row.state_changed_by,
                priority=row.priority,
                analyst_name=row.analyst_name,
                legal_transitions_for_caller=transitions,
                last_transition_actor=latest_actor.get(row.id),
            )
        )

    # Per-state counts give the frontend its tab badges in one trip.
    state_counts: dict[str, int] = {s.value: 0 for s in CaseLifecycleState}
    from sqlalchemy import func

    rows_by_state = (
        session.query(AnalysisCase.lifecycle_state, func.count(AnalysisCase.id))
        .group_by(AnalysisCase.lifecycle_state)
        .all()
    )
    for state_value, count in rows_by_state:
        if state_value in state_counts:
            state_counts[state_value] = int(count)

    return CaseQueueResponse(
        count=len(items),
        state_counts=state_counts,
        items=items,
    )


class TransitionRequest(BaseModel):
    to_state: str
    reason: str | None = None


class TransitionResponse(BaseModel):
    case_id: int
    from_state: str
    to_state: str
    actor: str
    role_at_transition: str
    occurred_at: datetime


@router.post(
    "/{case_id}/transition",
    response_model=TransitionResponse,
)
def transition_case(
    case_id: int,
    req: TransitionRequest,
    token_data: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> TransitionResponse:
    """Walk the case to ``to_state`` if the caller's roles allow it.

    Returns 400 for an unknown lifecycle state, 403 when the caller's
    roles don't intersect any legal-transition rule, 404 if the case
    is missing, 409 when (current_state, to_state) is illegal.
    """
    from app.services.case_workflow import (
        CaseNotFoundError,
        IllegalTransitionError,
        RoleNotPermittedError,
    )

    try:
        target = CaseLifecycleState(req.to_state)
    except ValueError as e:
        raise HTTPException(
            status_code=400, detail=f"unknown_lifecycle_state:{req.to_state}"
        ) from e

    workflow = CaseWorkflowService(session)
    actor = token_data.username or "anonymous"
    try:
        audit = workflow.transition(
            case_id=case_id,
            to_state=target,
            actor=actor,
            actor_roles=token_data.roles or [],
            reason=req.reason,
        )
    except CaseNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except IllegalTransitionError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except RoleNotPermittedError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e

    return TransitionResponse(
        case_id=audit.case_id,
        from_state=audit.from_state,
        to_state=audit.to_state,
        actor=audit.actor,
        role_at_transition=audit.role_at_transition,
        occurred_at=audit.occurred_at,
    )
