"""Sheshnaag candidate APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/candidates", tags=["Sheshnaag Candidates"])


class CandidateAssignRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analyst_name: str


@router.get("")
def list_candidates(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List research candidates for a tenant."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_candidates(tenant, limit=limit, status=status)


@router.post("/{candidate_id}/assign")
def assign_candidate(candidate_id: int, request: CandidateAssignRequest, session: Session = Depends(get_sync_session)):
    """Assign a candidate to an analyst."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).assign_candidate(tenant, candidate_id=candidate_id, analyst_name=request.analyst_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
