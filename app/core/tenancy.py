"""Tenant resolution helpers for public demo and private workspaces."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.v2 import Tenant

DEMO_TENANT_SLUG = "demo-public"


def get_or_create_demo_tenant(session: Session) -> Tenant:
    """Ensure the public demo tenant exists."""
    tenant = session.query(Tenant).filter(Tenant.slug == DEMO_TENANT_SLUG).first()
    if tenant:
        return tenant

    tenant = Tenant(
        slug=DEMO_TENANT_SLUG,
        name="Public Demo",
        description="Read-only demo tenant with seeded exposure and remediation data.",
        is_demo=True,
        is_read_only=True,
    )
    session.add(tenant)
    session.flush()
    return tenant


def resolve_tenant(
    session: Session,
    *,
    tenant_id: int | None = None,
    tenant_slug: str | None = None,
    default_to_demo: bool = True,
    access: str = "read",
) -> Tenant:
    """Resolve a tenant and enforce request-bound membership when present."""
    query = session.query(Tenant)

    tenant = None
    if tenant_id is not None:
        tenant = query.filter(Tenant.id == tenant_id, Tenant.is_active.is_(True)).first()
    elif tenant_slug:
        tenant = query.filter(Tenant.slug == tenant_slug, Tenant.is_active.is_(True)).first()
    elif default_to_demo:
        tenant = get_or_create_demo_tenant(session)

    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    from app.core.tenant_auth import current_request_token

    request_bound, token_data = current_request_token()
    if request_bound:
        from app.services.auth_service import AuthService

        AuthService(session).assert_tenant_access(tenant, token_data, access=access)

    return tenant


def require_writable_tenant(
    session: Session,
    *,
    tenant_id: int | None = None,
    tenant_slug: str | None = None,
) -> Tenant:
    """Resolve a tenant and reject writes to read-only demo workspaces."""
    tenant = resolve_tenant(
        session,
        tenant_id=tenant_id,
        tenant_slug=tenant_slug,
        default_to_demo=False,
        access="write",
    )
    if tenant.is_read_only:
        raise HTTPException(status_code=403, detail="This tenant is read-only")
    return tenant
