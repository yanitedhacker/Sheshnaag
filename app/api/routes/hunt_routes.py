"""V4 natural-language hunt API."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant
from app.services.hunt_service import HuntService

router = APIRouter(prefix="/api/v4/hunt", tags=["Sheshnaag V4 Hunt"])


class HuntRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)


@router.post("")
def run_hunt(
    payload: HuntRequest = Body(...),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    tenant = resolve_tenant(
        session,
        tenant_id=payload.tenant_id,
        tenant_slug=payload.tenant_slug,
        default_to_demo=False,
    )
    return HuntService(session).hunt(tenant, query=payload.query, limit=payload.limit)
