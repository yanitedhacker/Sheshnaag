"""V3 policy APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.malware_lab_service import MalwareLabService

router = APIRouter(prefix="/api/policy", tags=["Sheshnaag V3 Policy"])


class PolicyCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    name: str
    status: str = "active"
    policy: dict = Field(default_factory=dict)


@router.get("")
def list_policies(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return MalwareLabService(session).list_scope_policies(tenant)


@router.post("")
def create_policy(request: PolicyCreateRequest, session: Session = Depends(get_sync_session)):
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    return MalwareLabService(session).create_scope_policy(
        tenant,
        name=request.name,
        status=request.status,
        policy=request.policy,
    )
