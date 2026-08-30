"""HTTP request authentication context and tenant authorization tests."""

from __future__ import annotations

import importlib

import pytest
from fastapi import Depends, FastAPI, Query
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - register all SQLAlchemy tables
from app.core.config import settings
from app.core.database import Base
from app.core.security import create_access_token
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.models.v2 import Tenant, TenantMembership, TenantUser


def _tenant_auth_module():
    try:
        return importlib.import_module("app.core.tenant_auth")
    except ModuleNotFoundError:
        pytest.fail("app.core.tenant_auth is required for the HTTP authorization boundary")


def _context_client() -> TestClient:
    tenant_auth = _tenant_auth_module()
    app = FastAPI()
    app.add_middleware(tenant_auth.TenantAuthorizationContextMiddleware)

    @app.get("/context")
    def context():
        bound, token_data = tenant_auth.current_request_token()
        return {
            "bound": bound,
            "username": token_data.username if token_data else None,
            "user_id": token_data.user_id if token_data else None,
        }

    return TestClient(app)


def test_request_without_token_binds_anonymous_context():
    response = _context_client().get("/context")

    assert response.status_code == 200
    assert response.json() == {"bound": True, "username": None, "user_id": None}


def test_invalid_bearer_token_is_rejected_before_route_runs():
    response = _context_client().get(
        "/context",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


def test_valid_bearer_token_binds_verified_actor():
    token = create_access_token({"sub": "alice@example.invalid", "user_id": 41})

    response = _context_client().get(
        "/context",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "bound": True,
        "username": "alice@example.invalid",
        "user_id": 41,
    }


def _tenant_client(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    session = session_factory()
    tenant_a = Tenant(slug="tenant-a", name="Tenant A")
    tenant_b = Tenant(slug="tenant-b", name="Tenant B")
    demo = Tenant(
        slug="demo-public",
        name="Public Demo",
        is_demo=True,
        is_read_only=True,
    )
    lead = TenantUser(email="lead@example.invalid", password_hash="unused")
    reader = TenantUser(email="reader@example.invalid", password_hash="unused")
    session.add_all([tenant_a, tenant_b, demo, lead, reader])
    session.flush()
    session.add_all(
        [
            TenantMembership(
                tenant_id=tenant_a.id,
                user_id=lead.id,
                role="lab_lead",
                scopes=["tenant:read", "tenant:write"],
            ),
            TenantMembership(
                tenant_id=tenant_a.id,
                user_id=reader.id,
                role="read_only",
                scopes=["tenant:read"],
            ),
        ]
    )
    session.commit()

    lead_token = create_access_token({"sub": lead.email, "user_id": lead.id})
    reader_token = create_access_token({"sub": reader.email, "user_id": reader.id})
    session.close()

    def get_session():
        request_session = session_factory()
        try:
            yield request_session
        finally:
            request_session.close()

    tenant_auth = _tenant_auth_module()
    app = FastAPI()
    app.add_middleware(tenant_auth.TenantAuthorizationContextMiddleware)

    @app.get("/tenant")
    def read_tenant(
        tenant_slug: str = Query(...),
        session: Session = Depends(get_session),
    ):
        tenant = resolve_tenant(session, tenant_slug=tenant_slug, default_to_demo=False)
        return {"slug": tenant.slug}

    @app.post("/tenant")
    def write_tenant(
        tenant_slug: str = Query(...),
        session: Session = Depends(get_session),
    ):
        tenant = require_writable_tenant(session, tenant_slug=tenant_slug)
        return {"slug": tenant.slug}

    return TestClient(app), lead_token, reader_token


def test_missing_token_cannot_read_private_tenant(monkeypatch):
    client, _, _ = _tenant_client(monkeypatch)

    response = client.get("/tenant", params={"tenant_slug": "tenant-a"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required for private tenant access"


def test_member_cannot_select_another_private_tenant(monkeypatch):
    client, lead_token, _ = _tenant_client(monkeypatch)

    response = client.get(
        "/tenant",
        params={"tenant_slug": "tenant-b"},
        headers={"Authorization": f"Bearer {lead_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "No membership for this tenant"


def test_read_only_member_cannot_write_private_tenant(monkeypatch):
    client, _, reader_token = _tenant_client(monkeypatch)

    response = client.post(
        "/tenant",
        params={"tenant_slug": "tenant-a"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient role for this tenant"


def test_matching_lab_lead_can_write_private_tenant(monkeypatch):
    client, lead_token, _ = _tenant_client(monkeypatch)

    response = client.post(
        "/tenant",
        params={"tenant_slug": "tenant-a"},
        headers={"Authorization": f"Bearer {lead_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"slug": "tenant-a"}


def test_public_demo_read_remains_anonymous(monkeypatch):
    client, _, _ = _tenant_client(monkeypatch)

    response = client.get("/tenant", params={"tenant_slug": "demo-public"})

    assert response.status_code == 200
    assert response.json() == {"slug": "demo-public"}
