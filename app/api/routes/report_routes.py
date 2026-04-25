"""V3 malware-report APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/reports", tags=["Sheshnaag V3 Reports"])


class ReportCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    run_id: Optional[int] = None
    report_type: str = "incident_response"
    title: str
    created_by: str
    content: dict = Field(default_factory=dict)
    ai_metadata: dict = Field(default_factory=dict)


class ReportReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    report_id: int
    reviewer_name: str
    decision: str
    rationale: Optional[str] = None


@router.get("")
def list_reports(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_reports(tenant, analysis_case_id=analysis_case_id)


@router.post("")
def create_report(request: ReportCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_report(
            tenant,
            analysis_case_id=request.analysis_case_id,
            report_type=request.report_type,
            title=request.title,
            created_by=request.created_by,
            run_id=request.run_id,
            content=request.content,
            ai_metadata=request.ai_metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/review")
def review_report(request: ReportReviewRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).review_report(
            tenant,
            report_id=request.report_id,
            reviewer_name=request.reviewer_name,
            decision=request.decision,
            rationale=request.rationale,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{report_id}/export")
def export_report(
    report_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = require_writable_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug)
    try:
        return MalwareLabService(session).export_report(tenant, report_id=report_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False)
    try:
        archive = MalwareLabService(session).get_report_archive(tenant, report_id=report_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path=archive["path"], filename=archive["filename"], media_type="application/zip")
