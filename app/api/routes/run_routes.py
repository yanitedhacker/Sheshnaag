"""Sheshnaag validation run APIs."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/runs", tags=["Sheshnaag Runs"])


class RunLaunchRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    recipe_id: int
    revision_number: Optional[int] = None
    analyst_name: str
    launch_mode: str = "simulated"
    acknowledge_sensitive: bool = False
    workstation: Dict[str, Any] = Field(default_factory=dict)


@router.get("")
def list_runs(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List validation runs."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_runs(tenant)


@router.post("")
def launch_run(request: RunLaunchRequest, session: Session = Depends(get_sync_session)):
    """Launch or simulate a run."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).launch_run(
            tenant,
            recipe_id=request.recipe_id,
            revision_number=request.revision_number,
            analyst_name=request.analyst_name,
            workstation=request.workstation,
            launch_mode=request.launch_mode,
            acknowledge_sensitive=request.acknowledge_sensitive,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{run_id}")
def get_run(
    run_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Get run details."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        return SheshnaagService(session).get_run(tenant, run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
