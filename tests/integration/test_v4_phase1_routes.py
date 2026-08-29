"""Integration tests for V4 Phase 1 foundation APIs."""

from __future__ import annotations

import json

from fastapi import FastAPI, Header
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.authorization_routes import router as authorization_router
from app.api.routes.capability_routes import router as capability_router
from app.api.routes.ops_routes import router as ops_router
from app.core.database import Base, get_sync_session
from app.core.security import TokenData, verify_token


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


def override_verify_token(
    x_test_user: str = Header(default="anonymous"),
    x_test_roles: str = Header(default=""),
) -> TokenData:
    return TokenData(
        username=x_test_user,
        roles=[role for role in x_test_roles.split(",") if role],
        scopes=["read", "write"],
    )


test_app = FastAPI()
test_app.include_router(authorization_router)
test_app.include_router(capability_router)
test_app.include_router(ops_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
test_app.dependency_overrides[verify_token] = override_verify_token
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_authorization_lifecycle_and_capability_check(monkeypatch):
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "phase1-test-key")

    action_arguments = {
        "tenant_id": 7,
        "case_id": 42,
        "goal": "Review this exact case.",
        "max_steps": 3,
    }

    denied = client.get(
        "/api/v4/capability/check",
        params={
            "capability": "autonomous_agent_run",
            "scope": '{"tenant_id":7}',
            "actor": "forged-actor",
        },
        headers={"x-test-user": "analyst@example.com"},
    )
    assert denied.status_code == 200
    assert denied.json()["permitted"] is False
    assert denied.json()["reason"] == "exact_action_scope_required"

    requested = client.post(
        "/api/v4/authorization/requests",
        json={
            "capability": "autonomous_agent_run",
            "action": "autonomous_agent_run",
            "action_arguments": action_arguments,
            "requester": "forged-requester@example.com",
            "reason": "Phase 1 route contract test",
            "requested_ttl_seconds": 3600,
            "reviewers": [{"reviewer": "requester-controlled", "decision": "approve"}],
            "is_admin_approved": True,
        },
        headers={
            "x-test-user": "analyst@example.com",
            "x-test-roles": "analyst",
        },
    )
    assert requested.status_code == 201
    request_body = requested.json()
    assert request_body["status"] == "pending"
    assert request_body["requester"] == "analyst@example.com"
    assert request_body["artifact_id"] is None
    assert request_body["scope"]["action"] == "autonomous_agent_run"
    assert request_body["scope"]["action_digest"].startswith("sha256:")

    self_review = client.post(
        f"/api/v4/authorization/requests/{request_body['request_id']}/decisions",
        json={"decision": "approve", "note": "Must not self-approve."},
        headers={
            "x-test-user": "analyst@example.com",
            "x-test-roles": "senior_analyst",
        },
    )
    assert self_review.status_code == 409
    assert self_review.json()["detail"] == "requester_cannot_review"

    issued = client.post(
        f"/api/v4/authorization/requests/{request_body['request_id']}/decisions",
        json={"decision": "approve", "note": "Exact scope verified."},
        headers={
            "x-test-user": "reviewer@example.com",
            "x-test-roles": "reviewer",
        },
    )
    assert issued.status_code == 200
    assert issued.json()["status"] == "issued"
    artifact_id = issued.json()["artifact"]["artifact_id"]

    listed = client.get("/api/v4/authorization", params={"capability": "autonomous_agent_run"})
    assert listed.status_code == 200
    assert listed.json()["count"] == 1

    permitted = client.get(
        "/api/v4/capability/check",
        params={
            "capability": "autonomous_agent_run",
            "scope": json.dumps(request_body["scope"]),
            "actor": "forged-actor",
        },
        headers={"x-test-user": "analyst@example.com"},
    )
    assert permitted.status_code == 200
    assert permitted.json()["permitted"] is True
    assert permitted.json()["artifact_id"] == artifact_id

    changed_scope = dict(request_body["scope"])
    changed_scope["action_digest"] = "sha256:" + "f" * 64
    changed = client.get(
        "/api/v4/capability/check",
        params={
            "capability": "autonomous_agent_run",
            "scope": json.dumps(changed_scope),
            "actor": "forged-actor",
        },
        headers={"x-test-user": "analyst@example.com"},
    )
    assert changed.status_code == 200
    assert changed.json()["permitted"] is False
    assert changed.json()["reason"] == "no_matching_exact_action_artifact"

    root = client.get("/api/v4/authorization/chain/root")
    verify = client.get("/api/v4/authorization/chain/verify")
    assert root.status_code == 200
    assert verify.status_code == 200
    assert verify.json()["ok"] is True

    legacy = client.post(
        "/api/v4/authorization/request",
        json={
            "capability": "autonomous_agent_run",
            "reviewers": [{"reviewer": "requester-controlled"}],
            "is_admin_approved": True,
        },
        headers={"x-test-user": "analyst@example.com"},
    )
    assert legacy.status_code == 410
    assert legacy.json()["detail"] == "unsafe_authorization_flow_removed"

    revoked = client.post(
        f"/api/v4/authorization/{artifact_id}/revoke",
        json={"actor": "forged-reviewer", "reason": "done"},
        headers={"x-test-user": "reviewer@example.com"},
    )
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
