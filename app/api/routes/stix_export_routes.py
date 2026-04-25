"""V4 STIX 2.1 export route."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant
from app.services.stix_export_service import StixExportService

router = APIRouter(prefix="/api/v4/export/stix", tags=["Sheshnaag V4 STIX Export"])


@router.get("/{case_id}")
def export_case_stix(
    case_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    try:
        return StixExportService(session).export_case(tenant, case_id=case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
