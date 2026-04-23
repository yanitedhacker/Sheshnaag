"""V3 defang workflow APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/defang", tags=["Sheshnaag V3 Defang"])


class DefangCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    action_type: str
    title: str
    result_summary: Optional[str] = None
    payload: dict = Field(default_factory=dict)


class DefangReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    action_id: int
    reviewer_name: str
    decision: str
    rationale: Optional[str] = None


@router.get("")
def list_defang(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_defang_actions(tenant, analysis_case_id=analysis_case_id)


@router.post("")
def create_defang(request: DefangCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return MalwareLabService(session).create_defang_action(
        tenant,
        analysis_case_id=request.analysis_case_id,
        action_type=request.action_type,
        title=request.title,
        result_summary=request.result_summary,
        payload=request.payload,
    )


@router.post("/review")
def review_defang(request: DefangReviewRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).review_defang_action(
            tenant,
            action_id=request.action_id,
            reviewer_name=request.reviewer_name,
            decision=request.decision,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
