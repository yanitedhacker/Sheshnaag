"""Integration tests for V4 Phase 1 foundation APIs."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.authorization_routes import router as authorization_router
from app.api.routes.capability_routes import router as capability_router
from app.api.routes.ops_routes import router as ops_router
from app.core.database import Base, get_sync_session


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
test_app.include_router(authorization_router)
test_app.include_router(capability_router)
test_app.include_router(ops_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_authorization_lifecycle_and_capability_check(monkeypatch):
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "phase1-test-key")

    denied = client.get(
        "/api/v4/capability/check",
        params={"capability": "autonomous_agent_run", "scope": "{}", "actor": "analyst"},
    )
    assert denied.status_code == 200
    assert denied.json()["permitted"] is False

    issued = client.post(
        "/api/v4/authorization/request",
        json={
            "capability": "autonomous_agent_run",
            "scope": {},
            "requester": "analyst",
            "reason": "Phase 1 route contract test",
            "reviewers": [{"reviewer": "reviewer", "decision": "approve"}],
            "requested_ttl_seconds": 3600,
        },
    )
    assert issued.status_code == 200
    artifact_id = issued.json()["artifact_id"]

    listed = client.get("/api/v4/authorization", params={"capability": "autonomous_agent_run"})
    assert listed.status_code == 200
    assert listed.json()["count"] == 1

    permitted = client.get(
        "/api/v4/capability/check",
        params={"capability": "autonomous_agent_run", "scope": "{}", "actor": "analyst"},
    )
    assert permitted.status_code == 200
    assert permitted.json()["permitted"] is True
    assert permitted.json()["artifact_id"] == artifact_id

    root = client.get("/api/v4/authorization/chain/root")
    verify = client.get("/api/v4/authorization/chain/verify")
    assert root.status_code == 200
    assert verify.status_code == 200
    assert verify.json()["ok"] is True

    approved = client.post(f"/api/v4/authorization/{artifact_id}/approve", json={"reviewer": "reviewer"})
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "already_issued"

    revoked = client.post(f"/api/v4/authorization/{artifact_id}/revoke", json={"actor": "reviewer", "reason": "done"})
    assert revoked.status_code == 200
    assert revoked.json() == {"artifact_id": artifact_id, "revoked": True}


def test_ops_health_shape():
    response = client.get("/api/v4/ops/health")
    assert response.status_code == 200
    body = response.json()
    assert body["api"] == "ok"
    assert body["db"] == "ok"
    assert "redis" in body
    assert {"nft", "dnsmasq", "inetsim", "virsh", "limactl", "vol", "zeek", "tetragon"}.issubset(body["lab_deps"])
    assert "openai" in body["ai_providers"]
