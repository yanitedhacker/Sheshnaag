"""Exposure graph and attack path APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.graph_service import ExposureGraphService

router = APIRouter(prefix="/api/graph", tags=["Exposure Graph"])


@router.get("/attack-paths")
def get_attack_paths(
    tenant_slug: Optional[str] = Query(None, description="Tenant slug. Defaults to demo-public."),
    asset_id: Optional[int] = Query(None, description="Filter attack paths to a specific asset."),
    cve_id: Optional[str] = Query(None, description="Filter attack paths to a specific CVE ID."),
    limit: int = Query(5, ge=1, le=20, description="Number of top paths to return."),
    session: Session = Depends(get_sync_session),
):
    """Return graph nodes, edges, and top attack paths."""
    tenant = resolve_tenant(session, tenant_slug=tenant_slug, default_to_demo=True)
    service = ExposureGraphService(session)
    return service.get_attack_paths(tenant, asset_id=asset_id, cve_id=cve_id, limit=limit)
