"""Sheshnaag provenance APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/provenance", tags=["Sheshnaag Provenance"])


@router.get("")
def get_provenance(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List provenance and attestation records."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).get_provenance(tenant, run_id=run_id)
