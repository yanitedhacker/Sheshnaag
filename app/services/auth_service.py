"""Private tenant onboarding, login, and lightweight RBAC helpers."""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Sequence

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import TokenData, create_access_token, get_password_hash, verify_password
from app.models.v2 import Tenant, TenantMembership, TenantUser


ROLE_SCOPES: dict[str, list[str]] = {
    "viewer": ["tenant:read"],
    "analyst": ["tenant:read", "tenant:write", "model:feedback", "governance:read"],
    "admin": ["tenant:read", "tenant:write", "model:feedback", "governance:read", "governance:write"],
    "owner": [
        "tenant:read",
        "tenant:write",
        "model:feedback",
        "governance:read",
        "governance:write",
        "tenant:admin",
    ],
}

READ_ROLES = {"viewer", "analyst", "admin", "owner"}
WRITE_ROLES = {"analyst", "admin", "owner"}
ADMIN_ROLES = {"admin", "owner"}


class AuthService:
    """Manage private tenant users, memberships, and access tokens."""

    def __init__(self, session: Session):
        self.session = session

    def onboard_private_tenant(
        self,
        *,
        tenant_name: str,
        tenant_slug: str,
        admin_email: str,
        admin_password: str,
        admin_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, object]:
        """Create a private tenant with an owner membership and JWT."""
        existing_tenant = self.session.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if existing_tenant is not None:
            raise HTTPException(status_code=409, detail="Tenant slug already exists")

        user = self.session.query(TenantUser).filter(TenantUser.email == admin_email.lower()).first()
        if user is None:
            user = TenantUser(
                email=admin_email.lower(),
                full_name=admin_name,
                password_hash=get_password_hash(admin_password),
            )
            self.session.add(user)
            self.session.flush()
        elif not verify_password(admin_password, user.password_hash):
            raise HTTPException(status_code=409, detail="User already exists with a different password")

        tenant = Tenant(
            slug=tenant_slug,
            name=tenant_name,
            description=description,
            is_demo=False,
            is_read_only=False,
            is_active=True,
        )
        self.session.add(tenant)
        self.session.flush()

        membership = TenantMembership(
            tenant_id=tenant.id,
            user_id=user.id,
            role="owner",
            scopes=self._scopes_for_role("owner"),
        )
        self.session.add(membership)
        self.session.flush()

        token = self._build_token_for_user(user, memberships=[membership])
        return {
            "tenant": self._serialize_tenant(tenant),
            "user": self._serialize_user(user),
            "memberships": [self._serialize_membership(membership)],
            "token": token,
        }

    def login(self, *, email: str, password: str, tenant_slug: Optional[str] = None) -> Dict[str, object]:
        """Authenticate an existing workspace user."""
        user = self.session.query(TenantUser).filter(TenantUser.email == email.lower(), TenantUser.is_active.is_(True)).first()
        if user is None or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        query = self.session.query(TenantMembership).filter(TenantMembership.user_id == user.id)
        if tenant_slug:
            query = query.join(Tenant, Tenant.id == TenantMembership.tenant_id).filter(Tenant.slug == tenant_slug)
        memberships = query.all()
        if not memberships:
            raise HTTPException(status_code=403, detail="No memberships found for that workspace")

        return {
            "user": self._serialize_user(user),
            "memberships": [self._serialize_membership(membership) for membership in memberships],
            "token": self._build_token_for_user(user, memberships=memberships),
        }

    def me(self, token_data: TokenData) -> Dict[str, object]:
        """Return the current authenticated actor and memberships."""
        user = self.get_user_from_token(token_data)
        if user is None:
            raise HTTPException(status_code=401, detail="Authenticated user not found")
        memberships = self.session.query(TenantMembership).filter(TenantMembership.user_id == user.id).all()
        return {
            "user": self._serialize_user(user),
            "memberships": [self._serialize_membership(membership) for membership in memberships],
        }

    def get_user_from_token(self, token_data: Optional[TokenData]) -> Optional[TenantUser]:
        """Resolve a user from token claims if present."""
        if token_data is None or token_data.username in {None, "anonymous"}:
            return None

        user = None
        if token_data.user_id is not None:
            user = self.session.query(TenantUser).filter(TenantUser.id == token_data.user_id).first()
        if user is None and token_data.username:
            user = self.session.query(TenantUser).filter(TenantUser.email == token_data.username.lower()).first()
        return user

    def assert_tenant_access(
        self,
        tenant: Tenant,
        token_data: Optional[TokenData],
        *,
        access: str = "read",
    ) -> Optional[TenantMembership]:
        """Require that the token has access to a private tenant when auth is in use."""
        if tenant.is_demo:
            return None

        if token_data is None or token_data.username in {None, "anonymous"}:
            if settings.auth_enabled:
                raise HTTPException(status_code=401, detail="Authentication required for private tenant access")
            return None

        membership = (
            self.session.query(TenantMembership)
            .filter(TenantMembership.tenant_id == tenant.id, TenantMembership.user_id == token_data.user_id)
            .first()
        )
        if membership is None:
            raise HTTPException(status_code=403, detail="No membership for this tenant")

        allowed_roles: set[str]
        if access == "write":
            allowed_roles = WRITE_ROLES
        elif access == "admin":
            allowed_roles = ADMIN_ROLES
        else:
            allowed_roles = READ_ROLES

        if membership.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this tenant")
        return membership

    def resolve_private_tenant(
        self,
        *,
        token_data: Optional[TokenData],
        tenant_id: Optional[int] = None,
        tenant_slug: Optional[str] = None,
    ) -> Tenant:
        """Resolve a writable tenant, defaulting from auth context when possible."""
        query = self.session.query(Tenant).filter(Tenant.is_active.is_(True), Tenant.is_read_only.is_(False))
        tenant = None
        if tenant_id is not None:
            tenant = query.filter(Tenant.id == tenant_id).first()
        elif tenant_slug:
            tenant = query.filter(Tenant.slug == tenant_slug).first()
        elif token_data and token_data.memberships:
            tenant_ids = [membership.get("tenant_id") for membership in token_data.memberships if membership.get("tenant_id")]
            if len(tenant_ids) == 1:
                tenant = query.filter(Tenant.id == tenant_ids[0]).first()

        if tenant is None:
            raise HTTPException(status_code=400, detail="A private tenant id or slug is required for this action")
        return tenant

    @staticmethod
    def _scopes_for_role(role: str) -> list[str]:
        return list(ROLE_SCOPES.get(role, ROLE_SCOPES["viewer"]))

    def _build_token_for_user(self, user: TenantUser, *, memberships: Sequence[TenantMembership]) -> Dict[str, object]:
        scopes = sorted({scope for membership in memberships for scope in (membership.scopes or self._scopes_for_role(membership.role))})
        token_payload = {
            "sub": user.email,
            "user_id": user.id,
            "scopes": scopes,
            "memberships": [self._serialize_membership(membership) for membership in memberships],
        }
        token = create_access_token(token_payload)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 60 * 30,
        }

    @staticmethod
    def _serialize_tenant(tenant: Tenant) -> dict:
        return {
            "id": tenant.id,
            "slug": tenant.slug,
            "name": tenant.name,
            "description": tenant.description,
            "is_demo": tenant.is_demo,
            "is_read_only": tenant.is_read_only,
        }

    def _serialize_membership(self, membership: TenantMembership) -> dict:
        tenant = membership.tenant or self.session.query(Tenant).filter(Tenant.id == membership.tenant_id).first()
        return {
            "tenant_id": membership.tenant_id,
            "tenant_slug": tenant.slug if tenant else None,
            "tenant_name": tenant.name if tenant else None,
            "role": membership.role,
            "scopes": list(membership.scopes or self._scopes_for_role(membership.role)),
        }

    @staticmethod
    def _serialize_user(user: TenantUser) -> dict:
        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
        }
