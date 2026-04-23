"""V3 indicator APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/indicators", tags=["Sheshnaag V3 Indicators"])


class IndicatorCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    analysis_case_id: int
    indicator_kind: str
    value: str
    confidence: float = 0.7
    source: Optional[str] = None
    payload: dict = Field(default_factory=dict)


@router.get("")
def list_indicators(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    analysis_case_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_indicators(tenant, analysis_case_id=analysis_case_id)


@router.post("")
def create_indicator(request: IndicatorCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return MalwareLabService(session).create_indicator(
        tenant,
        analysis_case_id=request.analysis_case_id,
        indicator_kind=request.indicator_kind,
        value=request.value,
        confidence=request.confidence,
        source=request.source,
        payload=request.payload,
    )
