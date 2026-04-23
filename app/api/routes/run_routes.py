"""Sheshnaag validation run APIs."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.lab.interfaces import normalize_launch_mode
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
    analysis_mode: str = "cve_validation"
    sandbox_profile_id: Optional[int] = None
    specimen_ids: list[int] = Field(default_factory=list)
    egress_mode: Optional[str] = None
    ai_assist_enabled: bool = False
    ai_provider_hint: Optional[str] = None

    @field_validator("launch_mode", mode="before")
    @classmethod
    def normalize_mode(cls, value: Optional[str]) -> str:
        return normalize_launch_mode(value)


class RunPlanRequest(RunLaunchRequest):
    """Staged lifecycle: plan defaults to dry_run; set launch_mode for allocate/boot behavior."""

    launch_mode: str = "dry_run"


class RunActionRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None


@router.get("")
def list_runs(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List validation runs."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_runs(tenant)


@router.post("/plan")
def plan_run(request: RunPlanRequest, session: Session = Depends(get_sync_session)):
    """Create a planned run record with provider build_plan output (no allocation yet)."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).plan_run(
            tenant,
            recipe_id=request.recipe_id,
            revision_number=request.revision_number,
            analyst_name=request.analyst_name,
            workstation=request.workstation,
            launch_mode=request.launch_mode,
            acknowledge_sensitive=request.acknowledge_sensitive,
            analysis_mode=request.analysis_mode,
            sandbox_profile_id=request.sandbox_profile_id,
            specimen_ids=request.specimen_ids,
            egress_mode=request.egress_mode,
            ai_assist_enabled=request.ai_assist_enabled,
            ai_provider_hint=request.ai_provider_hint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
            analysis_mode=request.analysis_mode,
            sandbox_profile_id=request.sandbox_profile_id,
            specimen_ids=request.specimen_ids,
            egress_mode=request.egress_mode,
            ai_assist_enabled=request.ai_assist_enabled,
            ai_provider_hint=request.ai_provider_hint,
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


@router.post("/{run_id}/allocate")
def allocate_run_resources(
    run_id: int,
    request: RunActionRequest,
    session: Session = Depends(get_sync_session),
):
    """Allocate provider workspace/resources after POST /plan."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).allocate_run_resources(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{run_id}/boot")
def boot_run(
    run_id: int,
    request: RunActionRequest,
    session: Session = Depends(get_sync_session),
):
    """Boot guest after allocate."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).boot_run(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{run_id}/health")
def run_health(
    run_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Check the health of a running validation run."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        return SheshnaagService(session).run_health(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{run_id}/stop")
def stop_run(run_id: int, request: RunActionRequest, session: Session = Depends(get_sync_session)):
    """Stop a running validation run."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).stop_run(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{run_id}/teardown")
def teardown_run(run_id: int, request: RunActionRequest, session: Session = Depends(get_sync_session)):
    """Teardown a stopped or completed run."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).teardown_run(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{run_id}/destroy")
def destroy_run(run_id: int, request: RunActionRequest, session: Session = Depends(get_sync_session)):
    """Destroy all resources for a run."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).destroy_run(tenant, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
