"""Tier 3 integration tests: NL hunt, scheduled briefs, STIX 2.1 export."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import (
    brief_router,
    hunt_router,
    stix_export_router,
)
from app.core.database import Base, get_sync_session
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
from app.models.sheshnaag import AutonomousAgentRun, ScheduledBrief
from app.models.v2 import Tenant
from app.services.brief_service import BriefService
from app.services.hunt_service import HuntService
from app.services.stix_export_service import StixExportService


@pytest.fixture()
def app_and_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def _get_session():
        s = SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    app = FastAPI()
    app.include_router(hunt_router)
    app.include_router(brief_router)
    app.include_router(stix_export_router)
    app.dependency_overrides[get_sync_session] = _get_session

    # Seed: tenant + case + indicators + findings + specimen
    with SessionLocal() as seed:
        tenant = Tenant(slug="hunt-acme", name="ACME")
        seed.add(tenant)
        seed.flush()
        spec = Specimen(tenant_id=tenant.id, name="loader.bin", specimen_kind="elf")
        seed.add(spec)
        seed.flush()
        case = AnalysisCase(
            tenant_id=tenant.id,
            title="Operation WidgetTap",
            analyst_name="alice",
            specimen_ids=[spec.id],
        )
        seed.add(case)
        seed.flush()
        seed.add_all([
            IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind="domain",
                value="c2.evil.example.com",
                confidence=0.9,
            ),
            IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind="ipv4",
                value="198.51.100.42",
                confidence=0.8,
            ),
            BehaviorFinding(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                finding_type="network_c2",
                title="Beacon to c2.evil.example.com",
                severity="critical",
                confidence=0.92,
                payload={"attack_techniques": [{"technique_id": "T1071.001"}]},
            ),
            BehaviorFinding(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                finding_type="persistence",
                title="Cron job persistence noisy",
                severity="medium",
                confidence=0.6,
            ),
        ])
        seed.commit()
        tenant_id = tenant.id
        case_id = case.id
        spec_id = spec.id

    yield app, SessionLocal, tenant_id, case_id, spec_id
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# NL hunt
# ---------------------------------------------------------------------------


def test_hunt_parser_extracts_iocs_and_severities(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    with SessionLocal() as s:
        svc = HuntService(s)
        f = svc.parse(
            "show me high and critical findings for c2.evil.example.com or "
            "198.51.100.42 in the last 7 days mentioning beacon"
        )
        assert "domain" in f.indicators and "c2.evil.example.com" in f.indicators["domain"]
        assert "ipv4" in f.indicators and "198.51.100.42" in f.indicators["ipv4"]
        assert "high" in f.severities and "critical" in f.severities
        assert f.since is not None
        assert "beacon" in f.free_text


def test_hunt_finds_indicator_by_value(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    with SessionLocal() as s:
        tenant = s.get(Tenant, tenant_id)
        out = HuntService(s).hunt(tenant, query="c2.evil.example.com")
        assert out["count"]["indicators"] == 1
        assert out["matches"]["indicators"][0]["value"] == "c2.evil.example.com"


def test_hunt_filters_findings_by_severity(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    with SessionLocal() as s:
        tenant = s.get(Tenant, tenant_id)
        out = HuntService(s).hunt(tenant, query="critical")
        sevs = {f["severity"] for f in out["matches"]["findings"]}
        assert sevs == {"critical"}


def test_hunt_route_requires_auth_and_blocks_demo_default(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    client = TestClient(app)
    r = client.post("/api/v4/hunt", json={"query": "anything"})
    # AUTH_ENABLED defaults False in test envs => returns anonymous; missing
    # tenant_id => default_to_demo=False => 404 'Tenant not found'.
    assert r.status_code == 404
    r = client.post("/api/v4/hunt", json={"query": "beacon", "tenant_id": tenant_id})
    assert r.status_code == 200, r.text
    body = r.json()
    assert "matches" in body
    assert "parsed" in body


# ---------------------------------------------------------------------------
# Scheduled briefs
# ---------------------------------------------------------------------------


def test_brief_service_generates_and_persists(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    with SessionLocal() as s:
        tenant = s.get(Tenant, tenant_id)
        # Drop a fresh autonomous run so the brief includes agent activity
        s.add(AutonomousAgentRun(
            tenant_id=tenant.id,
            run_id="run_test_001",
            goal="brief sanity",
            status="completed",
            actor="alice",
            steps=[{"step": 1, "tool": "noop"}],
        ))
        s.commit()

        row = BriefService(s).generate_brief(tenant, period_hours=48)
        s.commit()

        assert row.id is not None
        assert row.tenant_id == tenant.id
        # Indicators + findings + agent run all seeded inside the period
        assert row.payload["counts"]["new_indicators"] >= 2
        assert row.payload["counts"]["new_findings"] >= 2
        assert row.payload["counts"]["agent_runs"] >= 1
        assert "T1071.001" in {tid for tid, _ in row.payload["top_attack_techniques"]}
        assert row.summary.startswith(f"Tenant {tenant.slug}")


def test_brief_routes_latest_and_list(app_and_session):
    app, SessionLocal, tenant_id, _, _ = app_and_session
    client = TestClient(app)

    # Generate two briefs ahead of time so /latest and /list have content
    with SessionLocal() as s:
        tenant = s.get(Tenant, tenant_id)
        BriefService(s).generate_brief(tenant, brief_type="ad_hoc")
        BriefService(s).generate_brief(tenant, brief_type="ad_hoc")
        s.commit()

    r = client.get("/api/v4/briefs/latest", params={"tenant_id": tenant_id})
    assert r.status_code == 200, r.text
    latest = r.json()
    assert latest["tenant_id"] == tenant_id
    assert "summary" in latest

    r = client.get("/api/v4/briefs", params={"tenant_id": tenant_id, "limit": 5})
    assert r.status_code == 200
    assert r.json()["count"] >= 2


def test_brief_latest_404_when_empty(app_and_session):
    app, SessionLocal, _, _, _ = app_and_session
    # Brand new tenant with no briefs => 404
    with SessionLocal() as s:
        empty = Tenant(slug="empty-soc", name="Empty")
        s.add(empty)
        s.commit()
        empty_id = empty.id

    client = TestClient(app)
    r = client.get("/api/v4/briefs/latest", params={"tenant_id": empty_id})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# STIX 2.1 export
# ---------------------------------------------------------------------------


def test_stix_export_service_builds_valid_bundle(app_and_session):
    app, SessionLocal, tenant_id, case_id, _ = app_and_session
    with SessionLocal() as s:
        tenant = s.get(Tenant, tenant_id)
        bundle = StixExportService(s).export_case(tenant, case_id=case_id)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = {obj["type"] for obj in bundle["objects"]}
    assert "identity" in types
    assert "indicator" in types
    assert "report" in types
    # Domain indicator should have the right STIX pattern
    domain_ind = next(
        o for o in bundle["objects"]
        if o["type"] == "indicator" and "c2.evil.example.com" in o["pattern"]
    )
    assert "domain-name:value" in domain_ind["pattern"]


def test_stix_export_route_returns_bundle(app_and_session):
    app, _, tenant_id, case_id, _ = app_and_session
    client = TestClient(app)
    r = client.get(f"/api/v4/export/stix/{case_id}", params={"tenant_id": tenant_id})
    assert r.status_code == 200, r.text
    bundle = r.json()
    assert bundle["type"] == "bundle"
    # Valid JSON re-roundtrip
    json.dumps(bundle)


def test_stix_export_404_for_unknown_case(app_and_session):
    app, _, tenant_id, _, _ = app_and_session
    client = TestClient(app)
    r = client.get("/api/v4/export/stix/99999", params={"tenant_id": tenant_id})
    assert r.status_code == 404


def test_export_external_tool_wires_to_stix(app_and_session):
    """The Phase A export_external stub now actually emits a STIX bundle."""

    app, SessionLocal, tenant_id, case_id, _ = app_and_session
    from app.services.ai_tools_registry import get_tool

    with SessionLocal() as s:
        tool = get_tool("export_external")
        result = tool.callable(
            bundle_id=str(case_id),
            target="stix",
            _context={"session": s, "tenant_id": tenant_id, "actor": "alice"},
        )
    assert result["accepted"] is True
    assert result["bundle"]["type"] == "bundle"
    assert result["object_count"] >= 3


def test_export_external_unknown_target_remains_unimplemented(app_and_session):
    app, SessionLocal, tenant_id, case_id, _ = app_and_session
    from app.services.ai_tools_registry import get_tool

    with SessionLocal() as s:
        result = get_tool("export_external").callable(
            bundle_id=str(case_id),
            target="taxii",
            _context={"session": s, "tenant_id": tenant_id, "actor": "alice"},
        )
    assert result["accepted"] is False
    assert "not yet implemented" in result["reason"]
