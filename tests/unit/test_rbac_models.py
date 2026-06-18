"""Unit tests for V5 RBAC models — Role, Permission, RolePermission."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401  registers all model tables
from app.core.database import Base
from app.models.rbac import Permission, Role, RolePermission


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
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


def test_role_round_trip(session):
    session.add(Role(name="analyst", description="Daily analyst work"))
    session.commit()

    rows = session.query(Role).all()
    assert len(rows) == 1
    assert rows[0].name == "analyst"
    assert rows[0].description == "Daily analyst work"
    assert rows[0].created_at is not None


def test_permission_round_trip(session):
    session.add(Permission(name="intel.read", description="Read intel dashboard"))
    session.commit()

    rows = session.query(Permission).all()
    assert len(rows) == 1
    assert rows[0].name == "intel.read"


def test_role_permission_link(session):
    session.add(Role(name="analyst", description="x"))
    session.add(Permission(name="intel.read", description="y"))
    session.commit()

    session.add(RolePermission(role_name="analyst", permission_name="intel.read"))
    session.commit()

    link = session.query(RolePermission).one()
    assert link.role_name == "analyst"
    assert link.permission_name == "intel.read"


def test_role_name_is_primary_key(session):
    session.add(Role(name="analyst", description="first"))
    session.commit()

    session.add(Role(name="analyst", description="second"))
    with pytest.raises(IntegrityError):
        session.commit()
