"""Integration tests for V5 lifecycle-aware case queue routes."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.routes.case_queue_routes import router as case_queue_router
from app.core.database import Base, get_sync_session
from app.core.security import TokenData, verify_token
from app.models.malware_lab import AnalysisCase
from app.models.v2 import Tenant
from app.services.case_workflow import CaseLifecycleState, CaseWorkflowService


@pytest.fixture()
def app_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    sess = Session()
    tenant = Tenant(slug="queue-test", name="Queue Test")
    sess.add(tenant)
    sess.flush()
    case = AnalysisCase(
        tenant_id=tenant.id,
        title="Suspicious loader",
        summary="Needs review",
        analyst_name="alice",
        lifecycle_state=CaseLifecycleState.REVIEW.value,
    )
    sess.add(case)
    sess.commit()
    sess.close()

    app = FastAPI()
    app.include_router(case_queue_router)

    def _override_session():
        s = Session()
        try:
            yield s
            s.commit()
        finally:
            s.close()

    app.dependency_overrides[get_sync_session] = _override_session
    app.dependency_overrides[verify_token] = lambda: TokenData(
        username="reviewer",
        roles=["reviewer"],
    )
    yield app
    engine.dispose()


def test_queue_filters_by_lifecycle_state(app_fixture):
    client = TestClient(app_fixture)
    r = client.get("/api/v5/cases/queue", params={"lifecycle_state": "review"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["items"][0]["lifecycle_state"] == "review"
    assert "ready_to_ship" in body["items"][0]["legal_transitions_for_caller"]


def test_queue_rejects_unknown_state(app_fixture):
    client = TestClient(app_fixture)
    r = client.get("/api/v5/cases/queue", params={"lifecycle_state": "bogus"})
    assert r.status_code == 400


def test_queue_empty_for_non_matching_state(app_fixture):
    client = TestClient(app_fixture)
    r = client.get("/api/v5/cases/queue", params={"lifecycle_state": "triage"})
    assert r.status_code == 200
    assert r.json()["count"] == 0
