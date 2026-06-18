"""Integration tests for V5 admin_roles routes.

Uses FastAPI TestClient against a fresh sqlite app instance with the
RBAC tables seeded directly. Exercises the public surface of
`/api/v5/admin/roles`, `/api/v5/admin/permissions`, and
`/api/v5/admin/users/{user_id}/role`.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.routes.admin_roles import router as admin_roles_router
from app.core.config import settings
from app.core.database import Base, get_sync_session
from app.core.security import TokenData, verify_token
from app.models.rbac import Permission, Role, RolePermission
from app.models.v2 import Tenant, TenantMembership, TenantUser


@pytest.fixture(autouse=True)
def _auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)


@pytest.fixture()
def app_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    sess = Session()
    sess.add_all(
        [
            Role(name="analyst", description="x"),
            Role(name="lab_lead", description="x"),
            Role(name="reviewer", description="x"),
            Permission(name="intel.read", description="x"),
            Permission(name="admin.roles.assign", description="x"),
        ]
    )
    sess.commit()
    sess.add_all(
        [
            RolePermission(role_name="analyst", permission_name="intel.read"),
            RolePermission(role_name="lab_lead", permission_name="intel.read"),
            RolePermission(role_name="lab_lead", permission_name="admin.roles.assign"),
        ]
    )
    sess.add(Tenant(id=1, slug="t1", name="T1"))
    sess.add(TenantUser(id=10, email="alice@example.com", password_hash="x"))
    sess.add(TenantMembership(tenant_id=1, user_id=10, role="analyst"))
    sess.commit()
    sess.close()

    app = FastAPI()
    app.include_router(admin_roles_router)

    def _override_session():
        s = Session()
        try:
            yield s
            s.commit()
        finally:
            s.close()

    app.dependency_overrides[get_sync_session] = _override_session

    yield app, Session
    engine.dispose()


def _client_as(app, roles):
    """Override verify_token to inject the chosen roles."""
    app.dependency_overrides[verify_token] = lambda: TokenData(username="caller", roles=roles)
    return TestClient(app)


def test_list_roles_open_to_authenticated(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["analyst"])
    r = client.get("/api/v5/admin/roles")
    assert r.status_code == 200
    names = {row["name"] for row in r.json()}
    assert "analyst" in names and "lab_lead" in names


def test_list_permissions_open_to_authenticated(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["analyst"])
    r = client.get("/api/v5/admin/permissions")
    assert r.status_code == 200
    assert "intel.read" in r.json()


def test_assign_role_requires_lab_lead(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["analyst"])  # not lab_lead
    r = client.post(
        "/api/v5/admin/users/10/role",
        json={"tenant_id": 1, "role": "reviewer"},
    )
    assert r.status_code == 403


def test_assign_role_lab_lead_succeeds(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["lab_lead"])
    r = client.post(
        "/api/v5/admin/users/10/role",
        json={"tenant_id": 1, "role": "reviewer"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "user_id": 10,
        "tenant_id": 1,
        "role": "reviewer",
        "previous_role": "analyst",
    }


def test_assign_role_unknown_role_400(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["lab_lead"])
    r = client.post(
        "/api/v5/admin/users/10/role",
        json={"tenant_id": 1, "role": "nonexistent_role"},
    )
    assert r.status_code == 400


def test_assign_role_unknown_user_404(app_fixture):
    app, _ = app_fixture
    client = _client_as(app, ["lab_lead"])
    r = client.post(
        "/api/v5/admin/users/999/role",
        json={"tenant_id": 1, "role": "reviewer"},
    )
    assert r.status_code == 404
