"""V3 analysis case APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/analysis-cases", tags=["Sheshnaag V3 Analysis Cases"])


class AnalysisCaseCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    title: str
    analyst_name: str
    summary: Optional[str] = None
    priority: str = "high"
    specimen_ids: list[int] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


@router.get("")
def list_analysis_cases(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_analysis_cases(tenant)


@router.get("/{case_id}")
def get_analysis_case(
    case_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        return MalwareLabService(session).get_analysis_case(tenant, case_id=case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("")
def create_analysis_case(request: AnalysisCaseCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_analysis_case(
            tenant,
            title=request.title,
            analyst_name=request.analyst_name,
            summary=request.summary,
            priority=request.priority,
            specimen_ids=request.specimen_ids,
            tags=request.tags,
            metadata=request.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
