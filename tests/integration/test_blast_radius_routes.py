"""Integration tests for the V4 malware blast-radius route."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.blast_radius_routes import router as blast_radius_router
from app.core.database import Base, get_sync_session
from app.models.asset import Asset
from app.models.malware_lab import AnalysisCase, BehaviorFinding, IndicatorArtifact
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
test_app.include_router(blast_radius_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def test_blast_radius_correlates_indicator_to_asset():
    session = TestingSession()
    try:
        tenant = Tenant(slug="blast-test", name="blast-test")
        session.add(tenant)
        session.flush()
        asset = Asset(
            tenant_id=tenant.id,
            name="c2-gateway",
            hostname="cdn-updates-example.invalid",
            asset_type="application",
            criticality="high",
            is_active=True,
        )
        session.add(asset)
        case = AnalysisCase(
            tenant_id=tenant.id,
            title="Blast case",
            status="open",
            priority="high",
            analyst_name="tester",
            specimen_ids=[],
        )
        session.add(case)
        session.flush()
        session.add(
            IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind="domain",
                value="cdn-updates-example.invalid",
                confidence=0.88,
                source="zeek",
            )
        )
        session.add(
            BehaviorFinding(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                finding_type="network:c2",
                title="C2 callback",
                severity="high",
                confidence=0.82,
                payload={"attack_techniques": ["T1071"]},
            )
        )
        session.commit()
        case_id = case.id
    finally:
        session.close()

    response = client.get(f"/api/v4/cases/{case_id}/blast-radius", params={"tenant_slug": "blast-test"})
    assert response.status_code == 200
    body = response.json()
    assert body["case"]["id"] == case_id
    assert body["affected_assets"][0]["hostname"] == "cdn-updates-example.invalid"
    assert body["recommended_actions"]
    assert body["confidence"] >= 0.55
