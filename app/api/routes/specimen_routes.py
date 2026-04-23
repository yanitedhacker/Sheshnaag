"""V3 specimen intake APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/specimens", tags=["Sheshnaag V3 Specimens"])


class SpecimenCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    name: str
    specimen_kind: str = "file"
    source_type: str = "upload"
    source_reference: str
    submitted_by: str
    summary: Optional[str] = None
    labels: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


@router.get("")
def list_specimens(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_specimens(tenant)


@router.post("")
def create_specimen(request: SpecimenCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_specimen(
            tenant,
            name=request.name,
            specimen_kind=request.specimen_kind,
            source_type=request.source_type,
            source_reference=request.source_reference,
            submitted_by=request.submitted_by,
            summary=request.summary,
            labels=request.labels,
            metadata=request.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
