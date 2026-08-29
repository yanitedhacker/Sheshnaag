"""Unit tests for the V5 require_role / require_permission FastAPI deps.

These exercise the dependency functions directly (no FastAPI app needed)
because the deps are plain callables that take a TokenData + Session and
return TokenData or raise HTTPException.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
import app.models  # noqa: F401  registers tables
from app.core.database import Base
from app.core.security import (
    TokenData,
    require_permission,
    require_role,
)
from app.models.rbac import Permission, Role, RolePermission


@pytest.fixture()
def session(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[Role.__table__, Permission.__table__, RolePermission.__table__],
    )
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    sess.add_all(
        [
            Role(name="analyst", description="x"),
            Role(name="lab_lead", description="x"),
            Role(name="reviewer", description="x"),
            Permission(name="intel.read", description="x"),
            Permission(name="policy.write", description="x"),
        ]
    )
    sess.commit()
    sess.add_all(
        [
            RolePermission(role_name="analyst", permission_name="intel.read"),
            RolePermission(role_name="lab_lead", permission_name="intel.read"),
            RolePermission(role_name="lab_lead", permission_name="policy.write"),
        ]
    )
    sess.commit()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


def _td(roles):
    return TokenData(username="alice", roles=roles)


def test_require_role_allows_match(session):
    dep = require_role("analyst")
    out = dep(token_data=_td(["analyst"]))
    assert out.username == "alice"


def test_require_role_denies_missing(session, monkeypatch):
    monkeypatch.setattr("app.core.security.settings.auth_enabled", True)
    dep = require_role("lab_lead")
    with pytest.raises(HTTPException) as exc:
        dep(token_data=_td(["analyst"]))
    assert exc.value.status_code == 403


def test_require_role_lab_lead_is_superuser(session):
    dep = require_role("reviewer")  # caller has lab_lead, not reviewer
    out = dep(token_data=_td(["lab_lead"]))
    assert out.username == "alice"


def test_require_permission_allowed(session):
    dep = require_permission("intel.read")
    out = dep(token_data=_td(["analyst"]), session=session)
    assert out.username == "alice"


def test_require_permission_denied(session, monkeypatch):
    monkeypatch.setattr("app.core.security.settings.auth_enabled", True)
    dep = require_permission("policy.write")
    with pytest.raises(HTTPException) as exc:
        dep(token_data=_td(["analyst"]), session=session)
    assert exc.value.status_code == 403


def test_require_permission_lab_lead_grants_all(session):
    dep = require_permission("policy.write")
    out = dep(token_data=_td(["lab_lead"]), session=session)
    assert out.username == "alice"


def test_token_data_roles_default_empty():
    td = TokenData(username="bob")
    assert td.roles == []
