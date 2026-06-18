"""V5 kill-criteria item 3 — OIDC provider registration and JIT contract."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.routes.auth_oidc import router as oidc_router
from app.core.database import Base, get_sync_session
from app.core.security import TokenData, verify_token
from app.models.rbac import Permission, Role, RolePermission
from app.models.v2 import Tenant
from app.services.oidc_service import OidcService


KEYCLOAK_ISSUER = "https://keycloak.example/realms/sheshnaag"
AUTHENTIK_ISSUER = "https://authentik.example/application/o/sheshnaag/"


def _seed_rbac(session) -> None:
    session.add(Tenant(id=1, slug="demo", name="Demo"))
    session.add(Role(name="analyst", description="analyst"))
    session.add(Role(name="read_only", description="read_only"))
    session.add(Permission(name="intel.read", description="intel.read"))
    session.add(RolePermission(role_name="analyst", permission_name="intel.read"))
    session.add(RolePermission(role_name="read_only", permission_name="intel.read"))
    session.commit()


@pytest.fixture()
def app_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    _seed_rbac(session)
    session.close()

    app = FastAPI()
    app.include_router(oidc_router)

    def _override_session():
        s = Session()
        try:
            yield s
            s.commit()
        finally:
            s.close()

    app.dependency_overrides[get_sync_session] = _override_session
    app.dependency_overrides[verify_token] = lambda: TokenData(
        username="lab_lead", roles=["lab_lead"]
    )
    yield app, Session
    engine.dispose()


def _install(session_factory, *, name: str, issuer: str) -> None:
    session = session_factory()
    try:
        OidcService(session).install_provider(
            name=name,
            issuer_url=issuer,
            client_id=f"{name}-client",
            client_secret_ref=f"OIDC_{name.upper()}_SECRET",
            redirect_uri=f"http://localhost:8000/api/v5/auth/oidc/{name}/callback",
            claim_mappings={
                "role_claim": "roles",
                "tenant_claim": "https://sheshnaag/tenant",
                "role_value_map": {},
            },
            default_tenant_id=1,
        )
        session.commit()
    finally:
        session.close()


def test_two_idps_registered_and_listed(app_fixture):
    """Gate item 3: at least two IdPs configured (Keycloak + Authentik)."""
    app, Session = app_fixture
    _install(Session, name="keycloak", issuer=KEYCLOAK_ISSUER)
    _install(Session, name="authentik", issuer=AUTHENTIK_ISSUER)

    client = TestClient(app)
    resp = client.get("/api/v5/auth/oidc/providers")
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert "keycloak" in names
    assert "authentik" in names


def test_jit_provisioning_assigns_role_from_claim(app_fixture):
    """JIT path assigns roles from ID token claim mapping."""
    app, Session = app_fixture
    _install(Session, name="keycloak", issuer=KEYCLOAK_ISSUER)
    session = Session()
    try:
        svc = OidcService(session)
        provider = svc.get_provider("keycloak")
        user, memberships = svc.jit_provision(
            provider,
            {
                "preferred_username": "analyst@example.com",
                "email": "analyst@example.com",
                "roles": ["analyst"],
                "https://sheshnaag/tenant": "demo",
            },
        )
        session.commit()
        assert user.email == "analyst@example.com"
        assert memberships[0]["role"] == "analyst"
        token = svc.mint_session_token(user, ["analyst"], memberships)
        assert token
    finally:
        session.close()
