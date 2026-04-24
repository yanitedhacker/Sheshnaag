"""V4 case-graph routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.graph_service import ExposureGraphService

router = APIRouter(prefix="/api/v4/cases", tags=["Sheshnaag V4 Case Graph"])


@router.get("/{case_id}/graph")
def get_case_graph(
    case_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    depth: int = Query(2, ge=0, le=5),
    session: Session = Depends(get_sync_session),
):
    """Return the case-anchored subgraph (case node + indicators + findings)."""

    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    payload = ExposureGraphService(session).case_graph(tenant, case_id=case_id, depth=depth)
    if payload.get("case") is None:
        raise HTTPException(status_code=404, detail="case_not_found")
    return payload
