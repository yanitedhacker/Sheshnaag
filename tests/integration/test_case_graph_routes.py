"""Integration tests for the V4 case-graph route."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.case_graph_routes import router as case_graph_router
from app.core.database import Base, get_sync_session
from app.models.malware_lab import AnalysisCase
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
test_app.include_router(case_graph_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_case_graph_returns_404_when_missing():
    response = client.get("/api/v4/cases/9999/graph", params={"tenant_slug": "demo-public"})
    # demo-public tenant is created lazily; when the case is missing we
    # expect 404. If tenant resolution fails we still expect a 4xx.
    assert response.status_code in {404, 400}


def test_case_graph_returns_synthetic_anchor_for_real_case():
    session = TestingSession()
    try:
        tenant = Tenant(slug="case-graph-test", name="case-graph-test")
        session.add(tenant)
        session.flush()
        case = AnalysisCase(
            tenant_id=tenant.id,
            title="Graph anchor case",
            status="open",
            priority="high",
            analyst_name="tester",
            specimen_ids=[],
        )
        session.add(case)
        session.commit()
        case_id = case.id
        tenant_slug = tenant.slug
    finally:
        session.close()

    response = client.get(f"/api/v4/cases/{case_id}/graph", params={"tenant_slug": tenant_slug})
    assert response.status_code == 200
    body = response.json()
    assert body["case"]["id"] == case_id
    # Synthetic case anchor node is always emitted.
    assert any(node["node_type"] == "case" for node in body["nodes"])
    assert body["depth"] == 2
