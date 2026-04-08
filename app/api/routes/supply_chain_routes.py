"""Supply-chain overview APIs."""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.supply_chain_service import SupplyChainService

router = APIRouter(prefix="/api/supply-chain", tags=["Supply Chain"])


@router.get("/overview")
def get_supply_chain_overview(
    tenant_slug: Optional[str] = None,
    tenant_id: Optional[int] = None,
    session: Session = Depends(get_sync_session),
):
    """Return supply-chain attack analysis and source-breadth metadata."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    service = SupplyChainService(session)
    return {
        "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
        **service.get_overview(tenant_id=tenant.id),
    }
