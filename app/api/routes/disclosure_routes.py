"""Sheshnaag disclosure bundle APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/disclosures", tags=["Sheshnaag Disclosures"])


class DisclosureBundleRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    run_id: int
    bundle_type: str = "vendor_disclosure"
    title: str
    signed_by: str
    evidence_ids: list[int] = Field(default_factory=list)
    redaction_notes: list[dict] = Field(default_factory=list)
    attachment_policy: dict = Field(default_factory=dict)
    review_checklist: dict = Field(default_factory=dict)
    reviewer_name: Optional[str] = None
    reviewer_role: Optional[str] = None
    confirm_external_export: bool = False


class DisclosureBundleReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    bundle_id: int
    reviewer_name: str
    reviewer_role: str = "reviewer"
    decision: str
    rationale: Optional[str] = None
    checklist: dict = Field(default_factory=dict)
    export_gating: dict = Field(default_factory=dict)


@router.get("")
def list_disclosures(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List disclosure bundles."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_disclosure_bundles(tenant)


@router.post("")
def create_disclosure_bundle(request: DisclosureBundleRequest, session: Session = Depends(get_sync_session)):
    """Create a signed disclosure bundle for a run."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).create_disclosure_bundle(
            tenant,
            run_id=request.run_id,
            bundle_type=request.bundle_type,
            title=request.title,
            signed_by=request.signed_by,
            evidence_ids=request.evidence_ids,
            redaction_notes=request.redaction_notes,
            attachment_policy=request.attachment_policy,
            review_checklist=request.review_checklist,
            reviewer_name=request.reviewer_name,
            reviewer_role=request.reviewer_role,
            confirm_external_export=request.confirm_external_export,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/review")
def review_disclosure_bundle(request: DisclosureBundleReviewRequest, session: Session = Depends(get_sync_session)):
    """Record review/approval state for a disclosure bundle."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).review_disclosure_bundle(
            tenant,
            bundle_id=request.bundle_id,
            reviewer_name=request.reviewer_name,
            reviewer_role=request.reviewer_role,
            decision=request.decision,
            rationale=request.rationale,
            checklist=request.checklist,
            export_gating=request.export_gating,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{bundle_id}/download")
def download_disclosure_bundle(
    bundle_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Download a previously exported disclosure bundle archive."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        archive = SheshnaagService(session).get_disclosure_bundle_archive(tenant, bundle_id=bundle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path=archive["path"], filename=archive["filename"], media_type="application/zip")
