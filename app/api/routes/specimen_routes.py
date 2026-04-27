"""V3 specimen intake APIs."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
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


def _parse_json_field(raw: Optional[str], *, default):
    if raw in {None, ""}:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON field: {exc.msg}") from exc


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


@router.post("/upload")
async def upload_specimen(
    tenant_id: Optional[int] = Form(None),
    tenant_slug: Optional[str] = Form(None),
    name: str = Form(...),
    specimen_kind: str = Form("file"),
    submitted_by: str = Form(...),
    summary: Optional[str] = Form(None),
    labels: Optional[str] = Form(None),
    metadata: Optional[str] = Form(None),
    file: UploadFile = File(...),
    session: Session = Depends(get_sync_session),
):
    tenant = require_writable_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug)
    parsed_labels = _parse_json_field(labels, default=[])
    parsed_metadata = _parse_json_field(metadata, default={})
    if not isinstance(parsed_labels, list):
        raise HTTPException(status_code=400, detail="labels must be a JSON array")
    if not isinstance(parsed_metadata, dict):
        raise HTTPException(status_code=400, detail="metadata must be a JSON object")
    data = await file.read()
    try:
        return MalwareLabService(session).create_specimen_from_bytes(
            tenant,
            name=name,
            specimen_kind=specimen_kind,
            data=data,
            filename=file.filename or name,
            content_type=file.content_type or "application/octet-stream",
            submitted_by=submitted_by,
            summary=summary,
            labels=[str(item) for item in parsed_labels],
            metadata=parsed_metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
