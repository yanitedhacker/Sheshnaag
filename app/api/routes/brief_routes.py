"""V4 scheduled-brief APIs."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant, require_writable_tenant
from app.services.brief_service import BriefService, serialize_brief

router = APIRouter(prefix="/api/v4/briefs", tags=["Sheshnaag V4 Briefs"])


class BriefGenerateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    brief_type: str = Field(default="ad_hoc", max_length=40)
    period_hours: int = Field(default=24, ge=1, le=720)


@router.get("/latest")
def latest_brief(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    brief_type: Optional[str] = Query(None, max_length=40),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    row = BriefService(session).latest(tenant, brief_type=brief_type)
    if row is None:
        raise HTTPException(status_code=404, detail="no_brief_available")
    return serialize_brief(row)


@router.get("")
def list_briefs(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    brief_type: Optional[str] = Query(None, max_length=40),
    limit: int = Query(20, ge=1, le=200),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    rows = BriefService(session).list_briefs(tenant, limit=limit, brief_type=brief_type)
    return {"items": [serialize_brief(r) for r in rows], "count": len(rows)}


@router.post("/generate")
def generate_brief(
    payload: BriefGenerateRequest = Body(...),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    """On-demand brief generation. Writes to read-only demo tenants is rejected."""

    tenant = require_writable_tenant(
        session, tenant_id=payload.tenant_id, tenant_slug=payload.tenant_slug
    )
    row = BriefService(session).generate_brief(
        tenant, brief_type=payload.brief_type, period_hours=payload.period_hours
    )
    return serialize_brief(row)
