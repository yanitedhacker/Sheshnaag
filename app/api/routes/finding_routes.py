"""V3 behavior finding APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/findings", tags=["Sheshnaag V3 Findings"])


class FindingCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    finding_type: str
    title: str
    severity: str = "medium"
    confidence: float = 0.5
    run_id: Optional[int] = None
    payload: dict = Field(default_factory=dict)


class FindingReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    finding_id: int
    reviewer_name: str
    decision: str
    rationale: Optional[str] = None


@router.get("")
def list_findings(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_behavior_findings(tenant, analysis_case_id=analysis_case_id)


@router.post("")
def create_finding(request: FindingCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return MalwareLabService(session).create_behavior_finding(
        tenant,
        analysis_case_id=request.analysis_case_id,
        finding_type=request.finding_type,
        title=request.title,
        severity=request.severity,
        confidence=request.confidence,
        run_id=request.run_id,
        payload=request.payload,
    )


@router.post("/review")
def review_finding(request: FindingReviewRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).review_behavior_finding(
            tenant,
            finding_id=request.finding_id,
            reviewer_name=request.reviewer_name,
            decision=request.decision,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
