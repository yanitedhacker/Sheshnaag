"""Unit tests for V5 RbacService."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers tables
from app.core.database import Base
from app.models.rbac import Permission, Role, RolePermission
from app.services.rbac import RbacService


@pytest.fixture()
def session():
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

    # Seed a representative slice of the v5a01 fixture set
    for name, desc in [
        ("read_only", "ro"),
        ("analyst", "an"),
        ("senior_analyst", "sa"),
        ("reviewer", "rv"),
        ("lab_lead", "ll"),
    ]:
        sess.add(Role(name=name, description=desc))
    for perm in ["intel.read", "policy.write", "ledger.read", "specimens.write"]:
        sess.add(Permission(name=perm, description=perm))
    sess.commit()

    # analyst can read intel + write specimens, NOT read ledger
    sess.add(RolePermission(role_name="analyst", permission_name="intel.read"))
    sess.add(RolePermission(role_name="analyst", permission_name="specimens.write"))
    # reviewer can read ledger (and intel)
    sess.add(RolePermission(role_name="reviewer", permission_name="intel.read"))
    sess.add(RolePermission(role_name="reviewer", permission_name="ledger.read"))
    # lab_lead has all
    for perm in ["intel.read", "policy.write", "ledger.read", "specimens.write"]:
        sess.add(RolePermission(role_name="lab_lead", permission_name=perm))
    sess.commit()

    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


def test_has_permission_direct(session):
    svc = RbacService(session)
    assert svc.has_permission("analyst", "intel.read") is True
    assert svc.has_permission("analyst", "policy.write") is False


def test_has_permission_lab_lead_all(session):
    svc = RbacService(session)
    for perm in ["intel.read", "policy.write", "ledger.read", "specimens.write"]:
        assert svc.has_permission("lab_lead", perm) is True


def test_has_any_permission(session):
    svc = RbacService(session)
    # Analyst alone cannot read ledger; reviewer alone can.
    assert svc.has_any_permission(["analyst"], "ledger.read") is False
    assert svc.has_any_permission(["analyst", "reviewer"], "ledger.read") is True


def test_unknown_role_returns_false(session):
    svc = RbacService(session)
    assert svc.has_permission("nope", "intel.read") is False


def test_validate_role_name(session):
    svc = RbacService(session)
    assert svc.validate_role_name("analyst") is True
    assert svc.validate_role_name("not_a_role") is False


def test_list_endpoints(session):
    svc = RbacService(session)
    assert svc.list_roles() == [
        "analyst",
        "lab_lead",
        "read_only",
        "reviewer",
        "senior_analyst",
    ]
    assert svc.list_permissions() == [
        "intel.read",
        "ledger.read",
        "policy.write",
        "specimens.write",
    ]


def test_permissions_for_role_sorted(session):
    svc = RbacService(session)
    assert svc.permissions_for_role("reviewer") == ["intel.read", "ledger.read"]
