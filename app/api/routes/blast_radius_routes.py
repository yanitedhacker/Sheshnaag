"""V4 malware blast-radius APIs."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.blast_radius_service import BlastRadiusService

router = APIRouter(prefix="/api/v4/cases", tags=["Sheshnaag V4 Blast Radius"])


@router.get("/{case_id}/blast-radius")
def get_case_blast_radius(
    case_id: int,
    depth: int = Query(1, ge=1, le=2),
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        return BlastRadiusService(session).case_blast_radius(tenant, case_id=case_id, depth=depth)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
