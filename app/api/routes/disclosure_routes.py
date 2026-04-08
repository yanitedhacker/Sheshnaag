"""Sheshnaag disclosure bundle APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
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
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
