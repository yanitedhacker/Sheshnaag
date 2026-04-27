"""V3 specimen revision APIs."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
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


def _parse_json_object(raw: Optional[str]) -> dict:
    if raw in {None, ""}:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid metadata JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="metadata must be a JSON object")
    return value


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


@router.post("/upload")
async def upload_specimen_revision(
    tenant_id: Optional[int] = Form(None),
    tenant_slug: Optional[str] = Form(None),
    specimen_id: int = Form(...),
    ingest_source: str = Form("upload"),
    parent_revision_id: Optional[int] = Form(None),
    metadata: Optional[str] = Form(None),
    file: UploadFile = File(...),
    session: Session = Depends(get_sync_session),
):
    tenant = require_writable_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug)
    data = await file.read()
    try:
        return MalwareLabService(session).create_specimen_revision_from_bytes(
            tenant,
            specimen_id=specimen_id,
            data=data,
            filename=file.filename or f"specimen-{specimen_id}",
            content_type=file.content_type or "application/octet-stream",
            ingest_source=ingest_source,
            parent_revision_id=parent_revision_id,
            metadata=_parse_json_object(metadata),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
