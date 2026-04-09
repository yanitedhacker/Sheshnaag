"""Integration tests for artifact review, provenance, and disclosure routes."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.artifact_routes import router as artifact_router
from app.api.routes.disclosure_routes import router as disclosure_router
from app.api.routes.provenance_routes import router as provenance_router
from app.core.database import Base, get_sync_session
from app.models import Asset
from app.services.auth_service import AuthService
from app.services.demo_seed_service import DemoSeedService
from app.services.sheshnaag_service import SheshnaagService

pytestmark = pytest.mark.integration

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
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
test_app.include_router(artifact_router)
test_app.include_router(provenance_router)
test_app.include_router(disclosure_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
client = TestClient(test_app)


@pytest.fixture(scope="module", autouse=True)
def seed_database():
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        DemoSeedService(session).seed()
        auth = AuthService(session)
        onboard = auth.onboard_private_tenant(
            tenant_name="Integration Routes Tenant",
            tenant_slug="integration-routes-private",
            admin_email="routes@sheshnaag.local",
            admin_password="supersecure123",
            admin_name="Routes Owner",
        )
        tenant = auth.resolve_private_tenant(token_data=None, tenant_id=onboard["tenant"]["id"])
        session.add(
            Asset(
                tenant_id=tenant.id,
                name="orders-api",
                asset_type="application",
                environment="production",
                criticality="high",
                business_criticality="high",
                installed_software=[{"vendor": "acme", "product": "acme-api-gateway", "version": "7.4.2"}],
            )
        )
        session.commit()

        service = SheshnaagService(session)
        candidate = service.list_candidates(tenant, limit=1)["items"][0]
        recipe = service.create_recipe(
            tenant,
            candidate_id=candidate["id"],
            name="Routes recipe",
            objective="Exercise artifact and disclosure routes.",
            created_by="Routes Owner",
            content={"command": ["bash", "-lc", "echo routes"], "network_policy": {"allow_egress_hosts": []}},
        )
        service.approve_recipe_revision(tenant, recipe_id=recipe["id"], revision_number=1, reviewer="Lead Reviewer")
        run = service.launch_run(
            tenant,
            recipe_id=recipe["id"],
            revision_number=1,
            analyst_name="Routes Owner",
            workstation={"hostname": "routes-host", "os_family": "macOS", "architecture": "arm64", "fingerprint": "routes-fp"},
            launch_mode="simulated",
            acknowledge_sensitive=False,
        )
        session.commit()
        globals()["SEEDED_RUN_ID"] = run["id"]
    finally:
        session.close()
    yield
    Base.metadata.drop_all(bind=engine)


def test_artifact_review_and_feedback_routes():
    session = TestingSession()
    try:
        tenant = AuthService(session).resolve_private_tenant(token_data=None, tenant_slug="integration-routes-private")
        artifacts = SheshnaagService(session).list_artifacts(tenant, run_id=globals()["SEEDED_RUN_ID"])
        detection_id = artifacts["detections"][0]["id"]
    finally:
        session.close()

    review = client.post(
        "/api/artifacts/review",
        json={
            "tenant_slug": "integration-routes-private",
            "artifact_family": "detection",
            "artifact_id": detection_id,
            "decision": "approved",
            "reviewer": "Lead Reviewer",
            "rationale": "Evidence supports promotion.",
        },
    )
    assert review.status_code == 200
    assert review.json()["status"] == "approved"

    feedback = client.post(
        "/api/artifacts/feedback",
        json={
            "tenant_slug": "integration-routes-private",
            "artifact_family": "detection",
            "artifact_id": detection_id,
            "reviewer": "Lead Reviewer",
            "feedback_type": "false_positive",
            "note": "Needs tighter narrowing.",
        },
    )
    assert feedback.status_code == 200
    assert feedback.json()["feedback"][0]["feedback_type"] == "false_positive"


def test_provenance_route_returns_enriched_run_payload():
    response = client.get(
        "/api/provenance",
        params={"tenant_slug": "integration-routes-private", "run_id": globals()["SEEDED_RUN_ID"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["manifest_summary"]["recipe_revision_id"] >= 1
    assert len(body["evidence_linkage"]) >= 1


def test_disclosure_route_exports_downloadable_archive():
    create = client.post(
        "/api/disclosures",
        json={
            "tenant_slug": "integration-routes-private",
            "run_id": globals()["SEEDED_RUN_ID"],
            "bundle_type": "vendor_disclosure",
            "title": "Integration bundle",
            "signed_by": "Routes Owner",
            "attachment_policy": {"include_raw_logs": False},
            "confirm_external_export": True,
        },
    )
    assert create.status_code == 200
    bundle = create.json()
    assert Path(bundle["archive"]["path"]).exists()
    assert bundle["manifest"]["export_audit"]["verification_status"] == "verified"
    assert bundle["manifest"]["attachment_policy"]["include_raw_logs"] is False

    download = client.get(
        f"/api/disclosures/{bundle['id']}/download",
        params={"tenant_slug": "integration-routes-private"},
    )
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/zip"
