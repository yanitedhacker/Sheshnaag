"""V3 prevention artifact APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/prevention", tags=["Sheshnaag V3 Prevention"])


class PreventionCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    artifact_type: str
    name: str
    body: str
    payload: dict = Field(default_factory=dict)


class PreventionReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    artifact_id: int
    reviewer_name: str
    decision: str
    rationale: Optional[str] = None


@router.get("")
def list_prevention(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_prevention_artifacts(tenant, analysis_case_id=analysis_case_id)


@router.post("")
def create_prevention(request: PreventionCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_prevention_artifact(
            tenant,
            analysis_case_id=request.analysis_case_id,
            artifact_type=request.artifact_type,
            name=request.name,
            body=request.body,
            payload=request.payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/review")
def review_prevention(request: PreventionReviewRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).review_prevention_artifact(
            tenant,
            artifact_id=request.artifact_id,
            reviewer_name=request.reviewer_name,
            decision=request.decision,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
