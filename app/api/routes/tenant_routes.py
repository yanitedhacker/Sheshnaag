"""Tenant onboarding and listing APIs."""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.models.v2 import Tenant
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/tenants", tags=["Tenants"])


class TenantOnboardRequest(BaseModel):
    tenant_name: str = Field(..., min_length=2, max_length=200)
    tenant_slug: str = Field(..., min_length=2, max_length=120)
    admin_email: str = Field(..., min_length=3)
    admin_password: str = Field(..., min_length=8)
    admin_name: Optional[str] = None
    description: Optional[str] = None


@router.post("/onboard")
def onboard_tenant(
    request: TenantOnboardRequest,
    session: Session = Depends(get_sync_session),
):
    """Create a private tenant and owner account."""
    service = AuthService(session)
    return service.onboard_private_tenant(
        tenant_name=request.tenant_name,
        tenant_slug=request.tenant_slug,
        admin_email=request.admin_email,
        admin_password=request.admin_password,
        admin_name=request.admin_name,
        description=request.description,
    )


@router.get("")
def list_tenants(
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """List visible tenants, preferring the caller's memberships when authenticated."""
    if token_data and token_data.memberships:
        return {"items": token_data.memberships}

    tenants = session.query(Tenant).filter(Tenant.is_active.is_(True)).order_by(Tenant.is_demo.desc(), Tenant.name).all()
    return {
        "items": [
            {
                "tenant_id": tenant.id,
                "tenant_slug": tenant.slug,
                "tenant_name": tenant.name,
                "role": "viewer" if tenant.is_demo else None,
                "scopes": ["tenant:read"] if tenant.is_demo else [],
                "is_demo": tenant.is_demo,
                "is_read_only": tenant.is_read_only,
            }
            for tenant in tenants
        ]
    }
