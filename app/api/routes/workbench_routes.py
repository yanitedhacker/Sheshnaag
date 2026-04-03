"""Workbench APIs for ranked remediation actions."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.workbench_service import WorkbenchService

router = APIRouter(prefix="/api/workbench", tags=["Workbench"])


@router.get("/summary")
def get_workbench_summary(
    tenant_slug: Optional[str] = Query(None, description="Tenant slug. Defaults to demo-public."),
    limit: int = Query(10, ge=1, le=50, description="Number of actions to return."),
    session: Session = Depends(get_sync_session),
):
    """Return ranked remediation actions for a tenant."""
    tenant = resolve_tenant(session, tenant_slug=tenant_slug, default_to_demo=True)
    service = WorkbenchService(session)
    return service.get_summary(tenant, limit=limit)
