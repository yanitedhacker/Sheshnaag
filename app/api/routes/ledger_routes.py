"""Sheshnaag analyst ledger APIs."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/ledger", tags=["Sheshnaag Ledger"])


@router.get("")
def get_ledger(
    tenant_slug: str | None = Query(None),
    tenant_id: int | None = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Return analyst contribution ledger entries."""
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    return SheshnaagService(session).get_ledger(tenant)
