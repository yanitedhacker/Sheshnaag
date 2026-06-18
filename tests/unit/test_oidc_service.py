"""V5 W1a OIDC service unit tests — provider CRUD, claim mapping, JIT provisioning."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers tables
from app.core.database import Base
from app.core.security import decode_token
from app.models.rbac import Permission, Role, RolePermission
from app.models.v2 import Tenant, TenantMembership, TenantUser
from app.services.oidc_service import (
    OidcCallbackError,
    OidcConfigError,
    OidcProviderNotFoundError,
    OidcService,
)


def _session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()

    sess.add(Tenant(id=1, slug="acme", name="ACME"))
    sess.add(Role(name="analyst", description="analyst"))
    sess.add(Role(name="read_only", description="read_only"))
    sess.add(Permission(name="intel.read", description="intel.read"))
    sess.add(RolePermission(role_name="analyst", permission_name="intel.read"))
    sess.add(RolePermission(role_name="read_only", permission_name="intel.read"))
    sess.commit()
    return sess


@pytest.mark.unit
def test_install_provider_and_reject_duplicate():
    session = _session()
    svc = OidcService(session)
    provider = svc.install_provider(
        name="keycloak-dev",
        issuer_url="https://idp.example.com/realms/sheshnaag",
        client_id="sheshnaag-web",
        client_secret_ref="OIDC_KEYCLOAK_CLIENT_SECRET",
        redirect_uri="http://localhost:8000/api/v5/auth/oidc/keycloak-dev/callback",
        claim_mappings={
            "role_value_map": {"sheshnaag-analyst": "analyst"},
        },
        default_tenant_id=1,
    )
    session.commit()
    assert provider.name == "keycloak-dev"
    assert provider.claim_mappings["role_claim"] == "groups"

    with pytest.raises(OidcConfigError, match="provider_exists"):
        svc.install_provider(
            name="keycloak-dev",
            issuer_url="https://idp.example.com/realms/other",
            client_id="x",
            client_secret_ref="OIDC_OTHER",
            redirect_uri="http://localhost/cb",
        )


@pytest.mark.unit
def test_map_claims_to_roles_translates_idp_groups():
    session = _session()
    svc = OidcService(session)
    provider = svc.install_provider(
        name="authentik",
        issuer_url="https://auth.example.com/application/o/sheshnaag/",
        client_id="sheshnaag",
        client_secret_ref="OIDC_AUTHENTIK_CLIENT_SECRET",
        redirect_uri="http://localhost/cb",
        claim_mappings={
            "role_claim": "groups",
            "role_value_map": {
                "sheshnaag-analyst": "analyst",
                "sheshnaag-readonly": "read_only",
            },
        },
        default_tenant_id=1,
    )
    session.commit()

    roles = svc.map_claims_to_roles(
        provider,
        {"groups": ["sheshnaag-analyst", "unknown-group", "sheshnaag-readonly"]},
    )
    assert roles == ["analyst", "read_only"]


@pytest.mark.unit
def test_jit_provision_creates_user_and_membership():
    session = _session()
    svc = OidcService(session)
    provider = svc.install_provider(
        name="keycloak",
        issuer_url="https://idp.example.com/realms/sheshnaag",
        client_id="sheshnaag",
        client_secret_ref="OIDC_KEYCLOAK_CLIENT_SECRET",
        redirect_uri="http://localhost/cb",
        claim_mappings={
            "role_value_map": {"analysts": "analyst"},
        },
        default_tenant_id=1,
    )
    session.commit()

    user, memberships = svc.jit_provision(
        provider,
        {
            "preferred_username": "alice",
            "email": "alice@acme.example",
            "groups": ["analysts"],
        },
    )
    session.commit()

    assert user.email == "alice@acme.example"
    assert memberships == [{"tenant_id": 1, "role": "analyst", "scopes": []}]
    membership = (
        session.query(TenantMembership)
        .filter_by(user_id=user.id, tenant_id=1)
        .one()
    )
    assert membership.role == "analyst"

    # Second login reuses the same user row.
    user2, _ = svc.jit_provision(
        provider,
        {
            "preferred_username": "alice",
            "email": "alice@acme.example",
            "groups": ["analysts"],
        },
    )
    assert user2.id == user.id


@pytest.mark.unit
def test_jit_provision_requires_assignable_tenant():
    session = _session()
    svc = OidcService(session)
    provider = svc.install_provider(
        name="orphan",
        issuer_url="https://idp.example.com/realms/orphan",
        client_id="sheshnaag",
        client_secret_ref="OIDC_ORPHAN_SECRET",
        redirect_uri="http://localhost/cb",
    )
    session.commit()

    with pytest.raises(OidcCallbackError, match="no_tenant_assignable"):
        svc.jit_provision(
            provider,
            {"preferred_username": "bob", "email": "bob@example.com"},
        )


@pytest.mark.unit
def test_mint_session_token_carries_roles_for_rbac():
    session = _session()
    svc = OidcService(session)
    user = TenantUser(email="carol@example.com", password_hash="!oidc-jit")
    session.add(user)
    session.commit()

    token = svc.mint_session_token(
        user,
        roles=["analyst"],
        memberships=[{"tenant_id": 1, "role": "analyst", "scopes": []}],
    )
    payload = decode_token(token)
    assert payload["roles"] == ["analyst"]
    assert payload["user_id"] == user.id


@pytest.mark.unit
def test_resolve_client_secret_reads_env(monkeypatch):
    session = _session()
    svc = OidcService(session)
    provider = svc.install_provider(
        name="env-test",
        issuer_url="https://idp.example.com",
        client_id="c",
        client_secret_ref="OIDC_TEST_SECRET",
        redirect_uri="http://localhost/cb",
        default_tenant_id=1,
    )
    session.commit()
    monkeypatch.setenv("OIDC_TEST_SECRET", "super-secret")
    assert OidcService.resolve_client_secret(provider) == "super-secret"


@pytest.mark.unit
def test_get_provider_missing_raises():
    session = _session()
    svc = OidcService(session)
    with pytest.raises(OidcProviderNotFoundError):
        svc.get_provider("missing")
