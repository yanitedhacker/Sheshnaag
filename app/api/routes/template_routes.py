"""Sheshnaag lab template APIs."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/templates", tags=["Sheshnaag Templates"])


@router.get("")
def list_templates(
    tenant_slug: str | None = Query(None),
    tenant_id: int | None = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List available lab templates."""
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    return SheshnaagService(session).list_templates(tenant)
