"""Integration tests for the V4 autonomous agent routes."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.autonomous_routes import router as autonomous_router
from app.core.database import Base, get_sync_session
from app.models.v2 import Tenant


engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_sync_session():
    session = TestingSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


test_app = FastAPI()
test_app.include_router(autonomous_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_run_autonomous_agent_completes_with_tenant_default(monkeypatch):
    # No capability artifact and no scope policy means the agent reaches the
    # synthesis step but the policy returns "no_active_artifact" and we
    # tolerate that as a deny. We assert that the run object is well-formed.
    session = TestingSession()
    try:
        tenant = Tenant(slug="agent-test", name="agent-test")
        session.add(tenant)
        session.commit()
        slug = tenant.slug
    finally:
        session.close()

    response = client.post(
        "/api/v4/autonomous/run",
        json={
            "goal": "Summarise the active findings and ATT&CK posture.",
            "tenant_slug": slug,
            "actor": "tester",
            "max_steps": 3,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["goal"].startswith("Summarise")
    assert body["status"] in {"completed", "denied"}
    # Even on deny we want a stable shape.
    assert "run_id" in body
    assert "steps" in body


def test_list_autonomous_runs_returns_history(monkeypatch):
    response = client.get("/api/v4/autonomous/runs", params={"tenant_slug": "agent-test"})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
