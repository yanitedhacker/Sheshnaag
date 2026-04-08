"""Sheshnaag evidence APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/evidence", tags=["Sheshnaag Evidence"])


@router.get("")
def list_evidence(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List evidence artifacts."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_evidence(tenant, run_id=run_id)
