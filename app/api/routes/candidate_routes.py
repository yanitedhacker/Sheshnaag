"""Sheshnaag candidate APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/candidates", tags=["Sheshnaag Candidates"])


class CandidateAssignRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analyst_name: str
    assigned_by: Optional[str] = None


class CandidateActionRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    reason: Optional[str] = None
    changed_by: Optional[str] = None


class CandidateMergeRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    merge_into_id: int
    merged_by: Optional[str] = None


class CandidateRecalculationRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    requested_by: str
    dry_run: bool = True
    reason: Optional[str] = None
    candidate_ids: list[int] = Field(default_factory=list)
    package_name: Optional[str] = None
    limit: Optional[int] = None


@router.get("")
def list_candidates(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    package_name: Optional[str] = Query(None),
    product_name: Optional[str] = Query(None),
    distro_hint: Optional[str] = Query(None),
    kev_only: Optional[bool] = Query(None),
    epss_min: Optional[float] = Query(None, ge=0.0, le=1.0),
    epss_max: Optional[float] = Query(None, ge=0.0, le=1.0),
    patch_available: Optional[bool] = Query(None),
    exploit_available: Optional[bool] = Query(None),
    min_observability: Optional[float] = Query(None, ge=0.0, le=1.0),
    max_observability: Optional[float] = Query(None, ge=0.0, le=1.0),
    assigned_to: Optional[str] = Query(None),
    assignment_state: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None, ge=0.0),
    max_score: Optional[float] = Query(None),
    sort_by: Optional[str] = Query(None),
    sort_order: Optional[str] = Query("desc"),
    session: Session = Depends(get_sync_session),
):
    """List research candidates with filtering, sorting, and pagination."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_candidates(
        tenant,
        limit=limit,
        offset=offset,
        status=status,
        package_name=package_name,
        product_name=product_name,
        distro_hint=distro_hint,
        kev_only=kev_only,
        epss_min=epss_min,
        epss_max=epss_max,
        patch_available=patch_available,
        exploit_available=exploit_available,
        min_observability=min_observability,
        max_observability=max_observability,
        assigned_to=assigned_to,
        assignment_state=assignment_state,
        min_score=min_score,
        max_score=max_score,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/{candidate_id}")
def get_candidate(
    candidate_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Get a single candidate by ID."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        svc = SheshnaagService(session)
        candidate = svc._get_candidate(tenant, candidate_id)
        return svc._candidate_payload(candidate)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{candidate_id}/assign")
def assign_candidate(candidate_id: int, request: CandidateAssignRequest, session: Session = Depends(get_sync_session)):
    """Assign a candidate to an analyst."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).assign_candidate(
            tenant, candidate_id=candidate_id, analyst_name=request.analyst_name, assigned_by=request.assigned_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{candidate_id}/defer")
def defer_candidate(candidate_id: int, request: CandidateActionRequest, session: Session = Depends(get_sync_session)):
    """Defer a candidate for later review."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).transition_candidate_status(
            tenant, candidate_id=candidate_id, new_status="deferred", reason=request.reason, changed_by=request.changed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Cannot transition" in str(exc) or "Invalid status" in str(exc) else 404, detail=str(exc)) from exc


@router.post("/{candidate_id}/reject")
def reject_candidate(candidate_id: int, request: CandidateActionRequest, session: Session = Depends(get_sync_session)):
    """Reject a candidate from the queue."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).transition_candidate_status(
            tenant, candidate_id=candidate_id, new_status="rejected", reason=request.reason, changed_by=request.changed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Cannot transition" in str(exc) or "Invalid status" in str(exc) else 404, detail=str(exc)) from exc


@router.post("/{candidate_id}/restore")
def restore_candidate(candidate_id: int, request: CandidateActionRequest, session: Session = Depends(get_sync_session)):
    """Restore a rejected, deferred, or archived candidate to the queue."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).transition_candidate_status(
            tenant, candidate_id=candidate_id, new_status="queued", reason=request.reason, changed_by=request.changed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Cannot transition" in str(exc) or "Invalid status" in str(exc) else 404, detail=str(exc)) from exc


@router.post("/{candidate_id}/archive")
def archive_candidate(candidate_id: int, request: CandidateActionRequest, session: Session = Depends(get_sync_session)):
    """Archive a candidate."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).transition_candidate_status(
            tenant, candidate_id=candidate_id, new_status="archived", reason=request.reason, changed_by=request.changed_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Cannot transition" in str(exc) or "Invalid status" in str(exc) else 404, detail=str(exc)) from exc


@router.post("/{candidate_id}/merge")
def merge_candidate(candidate_id: int, request: CandidateMergeRequest, session: Session = Depends(get_sync_session)):
    """Merge candidate as a duplicate of another candidate."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).merge_candidate_duplicate(
            tenant, candidate_id=candidate_id, merge_into_id=request.merge_into_id, merged_by=request.merged_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Cannot" in str(exc) or "cannot" in str(exc) else 404, detail=str(exc)) from exc


@router.get("/workload/summary")
def candidate_workload_summary(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Return per-analyst queue counts and unassigned totals."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).get_workload_summary(tenant)


@router.get("/recalculate/history")
def candidate_recalculation_history(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_sync_session),
):
    """List persisted candidate score recalculation runs."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_candidate_recalculation_runs(tenant, limit=limit)


@router.post("/recalculate")
def recalculate_candidates(request: CandidateRecalculationRequest, session: Session = Depends(get_sync_session)):
    """Recompute candidate scoring/explainability and persist an execution summary."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return SheshnaagService(session).recalculate_candidate_scores(
        tenant,
        requested_by=request.requested_by,
        dry_run=request.dry_run,
        reason=request.reason,
        candidate_ids=request.candidate_ids or None,
        package_name=request.package_name,
        limit=request.limit,
    )
