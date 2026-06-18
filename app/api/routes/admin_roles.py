"""V5 RBAC admin routes — list roles/permissions, assign role to a user.

Lab-lead-only writes; reads are open to any authenticated caller so the
frontend can render the role catalog in the operator console.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, require_role, verify_token
from app.models.v2 import TenantMembership, TenantUser
from app.services.rbac import RbacService

router = APIRouter(prefix="/api/v5/admin", tags=["Sheshnaag V5 Admin RBAC"])


class RoleEntry(BaseModel):
    name: str
    permissions: list[str]


class AssignRoleRequest(BaseModel):
    tenant_id: int
    role: str


class AssignRoleResponse(BaseModel):
    user_id: int
    tenant_id: int
    role: str
    previous_role: str


@router.get("/roles", response_model=list[RoleEntry])
def list_roles(
    _td: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> list[RoleEntry]:
    rbac = RbacService(session)
    return [
        RoleEntry(name=name, permissions=rbac.permissions_for_role(name))
        for name in rbac.list_roles()
    ]


@router.get("/permissions", response_model=list[str])
def list_permissions(
    _td: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> list[str]:
    return RbacService(session).list_permissions()


@router.post(
    "/users/{user_id}/role",
    response_model=AssignRoleResponse,
    dependencies=[Depends(require_role("lab_lead"))],
)
def assign_role(
    user_id: int,
    req: AssignRoleRequest,
    session: Session = Depends(get_sync_session),
) -> AssignRoleResponse:
    rbac = RbacService(session)
    if not rbac.validate_role_name(req.role):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown_role: {req.role}",
        )

    user = session.query(TenantUser).filter_by(id=user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"user_not_found: {user_id}",
        )

    membership = (
        session.query(TenantMembership).filter_by(user_id=user_id, tenant_id=req.tenant_id).first()
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="membership_not_found",
        )

    previous = membership.role
    membership.role = req.role
    session.commit()

    return AssignRoleResponse(
        user_id=user_id,
        tenant_id=req.tenant_id,
        role=req.role,
        previous_role=previous,
    )
