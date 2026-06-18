"""Integration tests for the V4 autonomous agent routes."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.autonomous_routes import router as autonomous_router
from app.core.database import Base, get_sync_session
from app.models.sheshnaag import AutonomousAgentRun
from app.models.v2 import Tenant
from app.services.capability_policy import (
    CapabilityPolicy,
    HmacDevSigner,
    IssuanceRequest,
    Reviewer,
    exact_action_scope,
)

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


def test_run_autonomous_agent_returns_only_committed_completion():
    goal = "Summarise the active findings and ATT&CK posture."
    session = TestingSession()
    try:
        tenant = Tenant(slug="agent-test", name="agent-test")
        session.add(tenant)
        session.flush()
        arguments = {
            "tenant_id": tenant.id,
            "goal": goal,
            "case_id": None,
            "max_steps": 3,
        }
        scope = exact_action_scope(
            "autonomous_agent_run",
            arguments,
            tenant_id=tenant.id,
        )
        artifact = CapabilityPolicy(
            session,
            signer=HmacDevSigner(key=b"autonomous-route-test-key"),
        ).issue(
            IssuanceRequest(
                capability="autonomous_agent_run",
                scope=scope,
                requester="analyst@example.com",
                reason="Route durability test.",
            ),
            [Reviewer("reviewer@example.com", "approve")],
        )
        session.commit()
        slug = tenant.slug
        artifact_id = artifact.artifact_id
    finally:
        session.close()

    response = client.post(
        "/api/v4/autonomous/run",
        json={
            "goal": goal,
            "tenant_slug": slug,
            "actor": "tester",
            "max_steps": 3,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["goal"].startswith("Summarise")
    assert body["status"] == "completed"
    assert body["disposition"]["code"] == "completed_read_only"
    assert body["authorization_artifact_id"] == artifact_id
    assert body["action_digest"] == scope["action_digest"]

    verification_session = TestingSession()
    try:
        durable = (
            verification_session.query(AutonomousAgentRun)
            .filter_by(run_id=body["run_id"])
            .one()
        )
        assert durable.status == "completed"
        assert durable.authorization_artifact_id == artifact_id
        assert durable.action_digest == scope["action_digest"]
    finally:
        verification_session.close()


def test_list_autonomous_runs_returns_history(monkeypatch):
    response = client.get("/api/v4/autonomous/runs", params={"tenant_slug": "agent-test"})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert body["replay"] == {
        "disposition": "bounded",
        "limit": 50,
        "maximum_limit": 100,
    }


def test_autonomous_replay_limit_is_bounded_by_api():
    session = TestingSession()
    try:
        tenant = session.query(Tenant).filter(Tenant.slug == "agent-replay-limit").first()
        if tenant is None:
            tenant = Tenant(slug="agent-replay-limit", name="agent-replay-limit")
            session.add(tenant)
            session.commit()
        slug = tenant.slug
    finally:
        session.close()

    response = client.get(
        "/api/v4/autonomous/runs",
        params={"tenant_slug": slug, "limit": 101},
    )

    assert response.status_code == 422


def test_autonomous_commit_failure_returns_503():
    session = TestingSession()
    try:
        tenant = Tenant(slug="agent-commit-failure", name="agent-commit-failure")
        session.add(tenant)
        session.commit()
        slug = tenant.slug
    finally:
        session.close()

    def override_failing_commit_session():
        failing_session = TestingSession()

        def fail_commit():
            raise RuntimeError("commit unavailable")

        failing_session.commit = fail_commit  # type: ignore[method-assign]
        try:
            yield failing_session
        finally:
            failing_session.rollback()
            failing_session.close()

    test_app.dependency_overrides[get_sync_session] = override_failing_commit_session
    try:
        response = client.post(
            "/api/v4/autonomous/run",
            json={
                "goal": "Persist the denial before the API returns.",
                "tenant_slug": slug,
                "actor": "tester",
                "max_steps": 3,
            },
        )
    finally:
        test_app.dependency_overrides[get_sync_session] = override_get_sync_session

    assert response.status_code == 503
    assert response.json()["detail"] == "autonomous_run_persistence_unavailable"
