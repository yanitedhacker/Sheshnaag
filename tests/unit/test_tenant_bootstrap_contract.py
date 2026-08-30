"""Fail-closed contracts for tenant bootstrap and onboarding."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.routes.tenant_routes import router as tenant_router
from app.core.config import settings
from app.core.database import Base, get_sync_session
from app.core.security import decode_token
from app.migrations.bootstrap import create_current_schema_snapshot
from app.models.v2 import Tenant, TenantMembership
from app.services.auth_service import ROLE_SCOPES, WRITE_ROLES


ROOT = Path(__file__).resolve().parents[2]
ONBOARD_PAYLOAD = {
    "tenant_name": "Release Tenant",
    "tenant_slug": "release-tenant",
    "admin_email": "release-lead@example.invalid",
    "admin_password": "correct-horse-battery-staple",
    "admin_name": "Release Lead",
}


def _tenant_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    app = FastAPI()
    app.include_router(tenant_router)

    def _session():
        session = Session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_sync_session] = _session
    return TestClient(app), Session, engine


def test_production_tenant_onboarding_is_closed_even_when_flag_is_true(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "tenant_onboarding_enabled", True, raising=False)
    client, Session, engine = _tenant_client()
    try:
        response = client.post("/api/tenants/onboard", json=ONBOARD_PAYLOAD)
        assert response.status_code == 403
        assert response.json()["detail"] == "tenant_onboarding_disabled"
        with Session() as session:
            assert session.query(TenantMembership).count() == 0
    finally:
        engine.dispose()


def test_nonproduction_onboarding_needs_explicit_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "tenant_onboarding_enabled", False, raising=False)
    client, Session, engine = _tenant_client()
    try:
        response = client.post("/api/tenants/onboard", json=ONBOARD_PAYLOAD)
        assert response.status_code == 403
        assert response.json()["detail"] == "tenant_onboarding_disabled"
        with Session() as session:
            assert session.query(TenantMembership).count() == 0
    finally:
        engine.dispose()


def test_opted_in_nonproduction_onboarding_creates_v5_lab_lead(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "tenant_onboarding_enabled", True, raising=False)
    client, _Session, engine = _tenant_client()
    try:
        response = client.post("/api/tenants/onboard", json=ONBOARD_PAYLOAD)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["memberships"][0]["role"] == "lab_lead"
        token_payload = decode_token(body["token"]["access_token"])
        assert token_payload["memberships"][0]["role"] == "lab_lead"
    finally:
        engine.dispose()


def test_demo_tenant_listing_uses_v5_read_only_role():
    client, Session, engine = _tenant_client()
    try:
        with Session() as session:
            session.add(
                Tenant(
                    slug="demo-v5-role",
                    name="Demo V5 Role",
                    is_demo=True,
                    is_read_only=True,
                    is_active=True,
                )
            )
            session.commit()
        response = client.get("/api/tenants")
        assert response.status_code == 200
        item = next(row for row in response.json()["items"] if row["tenant_slug"] == "demo-v5-role")
        assert item["role"] == "read_only"
    finally:
        engine.dispose()


def test_reviewer_is_not_admitted_to_legacy_tenant_write_routes():
    assert "tenant:write" not in ROLE_SCOPES["reviewer"]
    assert "governance:write" not in ROLE_SCOPES["reviewer"]
    assert "reviewer" not in WRITE_ROLES


def test_v6a03_repairs_legacy_owner_membership(tmp_path):
    database = tmp_path / "legacy-owner.sqlite3"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{database}"

    engine = create_engine(env["DATABASE_URL"])
    with engine.begin() as connection:
        create_current_schema_snapshot(connection, Base.metadata)
    engine.dispose()
    stamp = subprocess.run(
        [sys.executable, "-m", "alembic", "stamp", "v6a02"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert stamp.returncode == 0, stamp.stderr
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "INSERT INTO tenants (id, slug, name, is_demo, is_read_only, is_active) "
            "VALUES (101, 'legacy-private', 'Legacy Private', 0, 0, 1)"
        )
        connection.execute(
            "INSERT INTO tenant_users (id, email, password_hash, is_active, is_system) "
            "VALUES (201, 'legacy@example.invalid', 'not-used', 1, 0)"
        )
        connection.execute(
            "INSERT INTO tenant_memberships (tenant_id, user_id, role, scopes) "
            "VALUES (101, 201, 'owner', '[]')"
        )
        connection.execute("PRAGMA ignore_check_constraints = OFF")

    after = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert after.returncode == 0, after.stderr
    with sqlite3.connect(database) as connection:
        role = connection.execute(
            "SELECT role FROM tenant_memberships WHERE tenant_id = 101 AND user_id = 201"
        ).fetchone()
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    assert role == ("lab_lead",)
    assert revision == ("v6a03",)


def test_v6a03_refuses_to_stamp_database_missing_membership_table(tmp_path):
    database = tmp_path / "corrupt-v6a02.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE tenants (id INTEGER PRIMARY KEY)")
        connection.execute(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"
        )
        connection.execute("INSERT INTO alembic_version VALUES ('v6a02')")
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{database}"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode != 0
    assert "tenant_memberships_table_required" in result.stderr


def test_operator_bootstrap_is_idempotent_and_does_not_print_credentials(tmp_path):
    database = tmp_path / "bootstrap.sqlite3"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["DATABASE_URL"] = f"sqlite:///{database}"
    migrate = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert migrate.returncode == 0, migrate.stderr

    password = "operator-bootstrap-password"
    command = [
        sys.executable,
        str(ROOT / "scripts" / "v4" / "bootstrap_tenant_admin.py"),
        "--tenant-name",
        "Operator Tenant",
        "--tenant-slug",
        "operator-tenant",
        "--admin-email",
        "operator@example.invalid",
        "--admin-name",
        "Operator Lead",
        "--password-stdin",
    ]
    first = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    payload = json.loads(first.stdout)
    assert payload["status"] == "created"
    assert payload["role"] == "lab_lead"
    assert password not in first.stdout
    assert "operator@example.invalid" not in first.stdout
    assert "access_token" not in first.stdout

    repeated = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert repeated.returncode == 0, repeated.stderr
    assert json.loads(repeated.stdout)["status"] == "existing"


def test_bootstrap_contract_is_in_focused_ci_and_release_rehearsal():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    rehearsal = (ROOT / "scripts" / "sheshnaag_release_rehearsal.sh").read_text(
        encoding="utf-8"
    )
    acceptance = (ROOT / "scripts" / "sheshnaag_beta_acceptance.py").read_text(
        encoding="utf-8"
    )
    test_path = "tests/unit/test_tenant_bootstrap_contract.py"
    assert test_path in ci
    assert test_path in rehearsal
    assert test_path in acceptance
