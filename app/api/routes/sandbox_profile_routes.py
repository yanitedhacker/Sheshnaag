"""V3 sandbox profile APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/sandbox-profiles", tags=["Sheshnaag V3 Sandbox Profiles"])


class SandboxProfileCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    name: str
    profile_type: str
    provider_hint: str
    risk_level: str
    egress_mode: str
    config: dict = Field(default_factory=dict)


@router.get("")
def list_sandbox_profiles(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_sandbox_profiles(tenant)


@router.post("")
def create_sandbox_profile(request: SandboxProfileCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return MalwareLabService(session).create_sandbox_profile(
        tenant,
        name=request.name,
        profile_type=request.profile_type,
        provider_hint=request.provider_hint,
        risk_level=request.risk_level,
        egress_mode=request.egress_mode,
        config=request.config,
    )
