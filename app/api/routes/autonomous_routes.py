"""V4 Autonomous Analyst Agent routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant
from app.services.autonomous_agent import AutonomousAgent


def _actor_from_token(token_data: TokenData, fallback: str) -> str:
    """Bind actor identity to the JWT subject when one is present.

    When auth is disabled (anonymous fallback), the body-supplied actor is
    accepted so existing test/dev workflows keep working. When a real token
    is presented, its subject overrides the body field — preventing actor
    impersonation through user-controlled request data.
    """

    name = (token_data.username or "").strip()
    if name and name != "anonymous":
        return name
    return fallback

router = APIRouter(prefix="/api/v4/autonomous", tags=["Sheshnaag V4 Autonomous"])

# Process-level instance keeps the in-memory replay log. Callers that need
# durability should persist the returned payload onto their own AISession or
# AnalysisCase rows.
_AGENT: Optional[AutonomousAgent] = None


class AutonomousRunRequest(BaseModel):
    goal: str = Field(min_length=4, max_length=2000)
    tenant_slug: Optional[str] = None
    tenant_id: Optional[int] = None
    case_id: Optional[int] = None
    actor: str = "ui"
    max_steps: Optional[int] = Field(default=None, ge=1, le=10)


@router.post("/run")
def run_autonomous_agent(
    payload: AutonomousRunRequest = Body(...),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    tenant = resolve_tenant(
        session,
        tenant_id=payload.tenant_id,
        tenant_slug=payload.tenant_slug,
        default_to_demo=False,
    )
    global _AGENT
    if _AGENT is None:
        _AGENT = AutonomousAgent(session)
    else:
        _AGENT.session = session
    run = _AGENT.run(
        tenant,
        goal=payload.goal,
        actor=_actor_from_token(token_data, payload.actor),
        case_id=payload.case_id,
        max_steps=payload.max_steps,
    )
    return run.to_dict()


@router.get("/runs")
def list_autonomous_runs(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — gate only
):
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    global _AGENT
    if _AGENT is None:
        _AGENT = AutonomousAgent(session)
    else:
        _AGENT.session = session
    runs = _AGENT.list_runs(tenant=tenant)
    return {"items": runs, "count": len(runs)}
