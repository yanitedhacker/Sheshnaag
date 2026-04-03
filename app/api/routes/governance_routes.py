"""Approval workflow and audit APIs."""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.core.tenancy import resolve_tenant
from app.services.auth_service import AuthService
from app.services.governance_service import GovernanceService

router = APIRouter(prefix="/api/governance", tags=["Governance"])


class ApprovalRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    patch_id: str = Field(..., min_length=3)
    action_id: str = Field(..., min_length=3)
    approval_type: str = Field("signoff", min_length=3)
    approval_state: str = Field(..., min_length=3)
    maintenance_window: Optional[str] = None
    note: Optional[str] = None
    decided_by: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


@router.get("/approvals")
def list_approvals(
    tenant_slug: Optional[str] = None,
    tenant_id: Optional[int] = None,
    session: Session = Depends(get_sync_session),
):
    """List approvals for a tenant."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    service = GovernanceService(session)
    return service.list_approvals(tenant)


@router.post("/approvals")
def create_approval(
    request: ApprovalRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Create a change-window approval or sign-off for a private tenant."""
    auth_service = AuthService(session)
    if request.tenant_id is None and request.tenant_slug is None:
        tenant = auth_service.resolve_private_tenant(token_data=token_data)
    else:
        tenant = auth_service.resolve_private_tenant(token_data=token_data, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    auth_service.assert_tenant_access(tenant, token_data, access="admin")
    actor = auth_service.get_user_from_token(token_data)

    service = GovernanceService(session)
    return service.create_patch_approval(
        tenant,
        patch_id=request.patch_id,
        action_id=request.action_id,
        approval_type=request.approval_type,
        approval_state=request.approval_state,
        maintenance_window=request.maintenance_window,
        note=request.note,
        decided_by=request.decided_by,
        actor=actor,
        metadata=request.metadata,
    )


@router.get("/audit")
def list_audit(
    tenant_slug: Optional[str] = None,
    tenant_id: Optional[int] = None,
    session: Session = Depends(get_sync_session),
):
    """List append-only audit events for a tenant."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    service = GovernanceService(session)
    return service.list_audit_events(tenant)
