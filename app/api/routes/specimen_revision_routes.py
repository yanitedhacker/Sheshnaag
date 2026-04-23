"""V3 specimen revision APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/specimen-revisions", tags=["Sheshnaag V3 Specimen Revisions"])


class SpecimenRevisionCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    specimen_id: int
    content_ref: str
    ingest_source: str = "derived"
    parent_revision_id: Optional[int] = None
    metadata: dict = Field(default_factory=dict)


@router.get("")
def list_specimen_revisions(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    specimen_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_specimen_revisions(tenant, specimen_id=specimen_id)


@router.post("")
def create_specimen_revision(request: SpecimenRevisionCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return MalwareLabService(session).create_specimen_revision(
            tenant,
            specimen_id=request.specimen_id,
            content_ref=request.content_ref,
            ingest_source=request.ingest_source,
            parent_revision_id=request.parent_revision_id,
            metadata=request.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
