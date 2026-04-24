"""Integration tests for the V4 TAXII 2.1 server."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.taxii_routes import router as taxii_router, TAXII_CONTENT_TYPE
from app.core.database import Base, get_sync_session
from app.core.security import _session_dep
import app.models  # noqa: F401
from app.models.malware_lab import (
    AnalysisCase,
    IndicatorArtifact,
    MalwareReport,
    Specimen,
)
from app.models.v2 import Tenant
from app.services.capability_policy import (
    CapabilityPolicy,
    HmacDevSigner,
    IssuanceRequest,
    Reviewer,
)


# ---------------------------------------------------------------------------
# Shared engine / session / app
# ---------------------------------------------------------------------------


engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)


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
test_app.include_router(taxii_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session
test_app.dependency_overrides[_session_dep] = override_get_sync_session
client = TestClient(test_app)


# ---------------------------------------------------------------------------
# Seeding / artifact issuance
# ---------------------------------------------------------------------------


TENANT_ID: int
CASE_ID: int


def setup_module() -> None:
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        tenant = Tenant(
            slug="taxii-demo", name="Taxii Demo Tenant", is_active=True
        )
        session.add(tenant)
        session.flush()

        specimen = Specimen(
            tenant_id=tenant.id,
            name="wormy.bin",
            specimen_kind="file/pe",
            source_type="upload",
            status="quarantined",
            risk_level="high",
            labels=["worm"],
        )
        session.add(specimen)
        session.flush()

        case = AnalysisCase(
            tenant_id=tenant.id,
            title="Primary TAXII case",
            analyst_name="alice@example.com",
            specimen_ids=[specimen.id],
            tags=["ir"],
        )
        session.add(case)
        session.flush()

        session.add(
            IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind="sha256",
                value="d" * 64,
                confidence=0.88,
                source="sandbox",
            )
        )
        session.add(
            IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind="domain",
                value="evil.invalid",
                confidence=0.74,
                source="sandbox",
            )
        )
        session.add(
            MalwareReport(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                report_type="incident_response",
                title="TAXII IR Report",
                status="approved",
                created_by="alice@example.com",
                export_ready=True,
                content={"executive_summary": "Sample summary."},
            )
        )
        session.commit()
        globals()["TENANT_ID"] = tenant.id
        globals()["CASE_ID"] = case.id
    finally:
        session.close()


def teardown_module() -> None:
    Base.metadata.drop_all(bind=engine)


def _issue_external_disclosure_artifact():
    """Issue a valid external_disclosure artifact so routes pass the gate."""

    session = TestingSession()
    try:
        policy = CapabilityPolicy(session, signer=HmacDevSigner(key=b"taxii-test-key"))
        request = IssuanceRequest(
            capability="external_disclosure",
            scope={},  # empty scope permits any request scope
            requester="alice@example.com",
            reason="TAXII smoke test",
            is_admin_approved=True,
            requested_ttl=timedelta(hours=1),
        )
        policy.issue(
            request,
            [
                Reviewer("bob@example.com", "approve"),
                Reviewer("carol@example.com", "approve"),
            ],
        )
        session.commit()
    finally:
        session.close()


def _revoke_all_external_disclosure_artifacts():
    from app.models.capability import AuthorizationArtifact

    session = TestingSession()
    try:
        rows = (
            session.query(AuthorizationArtifact)
            .filter(AuthorizationArtifact.capability == "external_disclosure")
            .all()
        )
        policy = CapabilityPolicy(session, signer=HmacDevSigner(key=b"taxii-test-key"))
        for row in rows:
            if row.revoked_at is None:
                policy.revoke(row.artifact_id, actor="bob@example.com", reason="cleanup")
        session.commit()
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Capability gate
# ---------------------------------------------------------------------------


def test_discovery_denied_without_artifact():
    _revoke_all_external_disclosure_artifacts()
    resp = client.get("/taxii2/")
    assert resp.status_code == 403
    assert "capability_required" in resp.json()["detail"]


def test_list_collections_denied_without_artifact():
    _revoke_all_external_disclosure_artifacts()
    resp = client.get("/taxii2/api1/collections")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_discovery_ok_with_artifact():
    _revoke_all_external_disclosure_artifacts()
    _issue_external_disclosure_artifact()

    resp = client.get("/taxii2/")
    assert resp.status_code == 200
    assert TAXII_CONTENT_TYPE in resp.headers["content-type"].replace(" ", "")
    body = resp.json()
    assert "/taxii2/api1/" in body["api_roots"]


def test_api_root_ok():
    resp = client.get("/taxii2/api1/")
    assert resp.status_code == 200
    assert resp.json()["versions"] == [f"{TAXII_CONTENT_TYPE}"]


def test_list_collections_returns_per_tenant_label_collections():
    resp = client.get("/taxii2/api1/collections")
    assert resp.status_code == 200
    body = resp.json()
    assert "collections" in body
    ids = [c["id"] for c in body["collections"]]
    # Expect tenant-<id>--indicators, tenant-<id>--malware, tenant-<id>--reports, tenant-<id>--all
    assert f"tenant-{TENANT_ID}--indicators" in ids
    assert f"tenant-{TENANT_ID}--malware" in ids
    assert f"tenant-{TENANT_ID}--reports" in ids
    assert f"tenant-{TENANT_ID}--all" in ids


def test_get_single_collection_metadata():
    resp = client.get(f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == f"tenant-{TENANT_ID}--indicators"
    assert body["can_read"] is True


def test_get_collection_objects_returns_indicators():
    resp = client.get(f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects")
    assert resp.status_code == 200
    body = resp.json()
    assert "objects" in body
    # Both seeded indicators should appear.
    types = [o["type"] for o in body["objects"]]
    assert types.count("indicator") == 2


def test_get_collection_objects_all_returns_everything():
    resp = client.get(f"/taxii2/api1/collections/tenant-{TENANT_ID}--all/objects")
    assert resp.status_code == 200
    body = resp.json()
    types = {o["type"] for o in body["objects"]}
    assert "indicator" in types
    assert "malware" in types
    assert "report" in types


def test_get_collection_objects_with_range_returns_206():
    resp = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--all/objects",
        headers={"Range": "items=0-0"},
    )
    assert resp.status_code == 206
    assert "content-range" in {k.lower() for k in resp.headers.keys()}
    body = resp.json()
    assert len(body["objects"]) == 1


def test_fetch_single_object_by_id():
    listing = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects"
    ).json()
    first_id = listing["objects"][0]["id"]
    resp = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects/{first_id}"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["objects"][0]["id"] == first_id


def test_fetch_unknown_object_returns_404():
    resp = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects/indicator--ffffffff-ffff-ffff-ffff-ffffffffffff"
    )
    assert resp.status_code == 404


def test_manifest_lists_per_object_metadata():
    resp = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/manifest"
    )
    assert resp.status_code == 200
    body = resp.json()
    for entry in body["objects"]:
        assert entry["media_type"] == "application/stix+json;version=2.1"
        assert "id" in entry
        assert "version" in entry


def test_unknown_collection_returns_404():
    resp = client.get("/taxii2/api1/collections/tenant-99999--indicators")
    assert resp.status_code == 404


def test_post_objects_validates_and_returns_status():
    valid_obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--11111111-2222-3333-4444-555555555555",
        "created": "2026-04-24T10:00:00Z",
        "modified": "2026-04-24T10:00:00Z",
        "pattern": "[file:hashes.'SHA-256' = 'cafebabe']",
        "pattern_type": "stix",
        "valid_from": "2026-04-24T10:00:00Z",
        "indicator_types": ["malicious-activity"],
        "labels": ["incoming"],
    }
    malformed_obj = {"type": "indicator", "id": "indicator--bad-id"}

    resp = client.post(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects",
        json={"objects": [valid_obj, malformed_obj]},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "complete"
    assert body["success_count"] == 1
    assert body["failure_count"] == 1
    assert body["successes"][0]["id"] == valid_obj["id"]


def test_post_then_get_returns_ingested_object():
    ingested = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--22222222-3333-4444-5555-666666666666",
        "created": "2026-04-24T11:00:00Z",
        "modified": "2026-04-24T11:00:00Z",
        "pattern": "[domain-name:value = 'ingested.invalid']",
        "pattern_type": "stix",
        "valid_from": "2026-04-24T11:00:00Z",
        "indicator_types": ["malicious-activity"],
        "labels": ["partner-feed"],
    }
    post = client.post(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects",
        json={"objects": [ingested]},
    )
    assert post.status_code == 202
    listing = client.get(
        f"/taxii2/api1/collections/tenant-{TENANT_ID}--indicators/objects"
    )
    assert listing.status_code == 200
    found = [o for o in listing.json()["objects"] if o["id"] == ingested["id"]]
    assert found
