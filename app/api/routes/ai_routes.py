"""V3 AI provider and draft session APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/ai", tags=["Sheshnaag V3 AI"])


class AISessionCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    provider_key: str
    capability: str
    prompt: str
    grounding: dict = Field(default_factory=dict)
    created_by: str


class AISessionReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    session_id: int
    reviewer_name: str
    decision: str
    rationale: Optional[str] = None


@router.get("/providers")
def list_ai_providers(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_ai_providers(tenant)


@router.get("/sessions")
def list_ai_sessions(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_ai_sessions(tenant, analysis_case_id=analysis_case_id)


@router.post("/sessions")
def create_ai_session(request: AISessionCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_ai_session(
            tenant,
            analysis_case_id=request.analysis_case_id,
            provider_key=request.provider_key,
            capability=request.capability,
            prompt=request.prompt,
            grounding=request.grounding,
            created_by=request.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sessions/review")
def review_ai_session(request: AISessionReviewRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).review_ai_session(
            tenant,
            session_id=request.session_id,
            reviewer_name=request.reviewer_name,
            decision=request.decision,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
