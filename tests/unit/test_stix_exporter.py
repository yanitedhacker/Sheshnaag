"""Unit tests for the V4 STIX 2.1 exporter."""

from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    MalwareReport,
    Specimen,
)
from app.models.v2 import Tenant
from app.services.stix_exporter import (
    STIX_SPEC_VERSION,
    StixExporter,
    _build_indicator_pattern,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


@pytest.fixture()
def seeded_case(session):
    """Seed a minimal tenant + case + 1 specimen + 2 indicators + 1 finding + 1 report."""

    tenant = Tenant(slug="demo", name="Demo Tenant", is_active=True)
    session.add(tenant)
    session.flush()

    specimen = Specimen(
        tenant_id=tenant.id,
        name="evil.exe",
        specimen_kind="file/pe",
        source_type="upload",
        status="quarantined",
        risk_level="high",
        summary="Known-bad dropper.",
        labels=["trojan"],
        latest_revision_number=1,
    )
    session.add(specimen)
    session.flush()

    case = AnalysisCase(
        tenant_id=tenant.id,
        title="Case 1",
        summary="STIX export smoke case",
        analyst_name="alice@example.com",
        specimen_ids=[specimen.id],
        tags=["incident"],
    )
    session.add(case)
    session.flush()

    ind_hash = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="sha256",
        value="a" * 64,
        confidence=0.92,
        source="sandbox",
    )
    ind_dom = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="domain",
        value="bad.invalid",
        confidence=0.75,
        source="sandbox",
    )
    session.add_all([ind_hash, ind_dom])

    finding = BehaviorFinding(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        finding_type="network_beacon",
        title="Suspicious DNS beacon",
        severity="high",
        confidence=0.88,
        status="reviewed",
    )
    session.add(finding)

    report = MalwareReport(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        report_type="incident_response",
        title="Case 1 — IR Report",
        status="approved",
        created_by="alice@example.com",
        export_ready=True,
        content={"executive_summary": "Dropper observed beaconing to bad.invalid."},
    )
    session.add(report)

    session.flush()
    return tenant, case


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------


def test_build_indicator_pattern_hashes():
    p = _build_indicator_pattern("sha256", "abc123")
    assert p == "[file:hashes.'SHA-256' = 'abc123']"


def test_build_indicator_pattern_url_domain_ip():
    assert _build_indicator_pattern("url", "http://x/y") == "[url:value = 'http://x/y']"
    assert _build_indicator_pattern("domain", "bad.tld") == "[domain-name:value = 'bad.tld']"
    assert _build_indicator_pattern("ip", "8.8.8.8") == "[ipv4-addr:value = '8.8.8.8']"
    assert _build_indicator_pattern("ip", "::1") == "[ipv6-addr:value = '::1']"


def test_build_indicator_pattern_unknown_returns_none():
    assert _build_indicator_pattern("something-weird", "value") is None


# ---------------------------------------------------------------------------
# Bundle export
# ---------------------------------------------------------------------------


def test_export_case_emits_expected_sdos(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")

    types = [o["type"] for o in bundle["objects"]]
    # Expect at least: 1 malware, 2 indicators, 2 indicator→malware
    # relationships, 1 indicator↔indicator co-occurrence, 1 sighting,
    # 1 observed-data, 1 report.
    assert types.count("malware") == 1
    assert types.count("indicator") == 2
    assert types.count("relationship") >= 3
    assert types.count("sighting") == 1
    assert types.count("observed-data") >= 1
    assert types.count("report") == 1


def test_export_validates_clean_against_spec(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)
    errors = exporter.validate_bundle(bundle)
    assert errors == [], f"expected zero violations, got: {errors}"


def test_export_fields_pass_spec_details(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)

    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["spec_version"] == STIX_SPEC_VERSION
    assert indicator["pattern_type"] == "stix"
    assert indicator["pattern"].startswith("[")
    assert indicator["valid_from"].endswith("Z")
    assert "indicator_types" in indicator
    assert indicator["indicator_types"]
    assert "labels" in indicator and indicator["labels"]

    malware = next(o for o in bundle["objects"] if o["type"] == "malware")
    assert malware["is_family"] is False
    assert malware["malware_types"]
    assert malware["created"].endswith("Z")
    assert malware["modified"].endswith("Z")

    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report["published"].endswith("Z")
    assert report["object_refs"]
    assert all(isinstance(ref, str) and "--" in ref for ref in report["object_refs"])


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_validate_detects_tampered_timestamp(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)
    # Break the ISO-8601 Z requirement on the first indicator.
    tampered = copy.deepcopy(bundle)
    indicator = next(o for o in tampered["objects"] if o["type"] == "indicator")
    indicator["created"] = "2026-04-24 10:00:00"  # missing Z, wrong separator
    errors = exporter.validate_bundle(tampered)
    assert any("ISO-8601" in e for e in errors), errors


def test_validate_detects_missing_required_field(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)
    tampered = copy.deepcopy(bundle)
    malware = next(o for o in tampered["objects"] if o["type"] == "malware")
    malware.pop("malware_types")
    errors = exporter.validate_bundle(tampered)
    assert any("malware_types" in e for e in errors), errors


def test_validate_detects_malformed_id(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)
    tampered = copy.deepcopy(bundle)
    indicator = next(o for o in tampered["objects"] if o["type"] == "indicator")
    indicator["id"] = "indicator--not-a-uuid"
    errors = exporter.validate_bundle(tampered)
    assert any("STIX id" in e for e in errors), errors


def test_validate_flags_duplicate_ids(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id)
    tampered = copy.deepcopy(bundle)
    # Duplicate the first malware.
    first = next(o for o in tampered["objects"] if o["type"] == "malware")
    tampered["objects"].append(copy.deepcopy(first))
    errors = exporter.validate_bundle(tampered)
    assert any("duplicate id" in e for e in errors), errors


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_reexport_yields_same_sdo_ids(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    a = exporter.export_case(tenant, case.id)
    b = exporter.export_case(tenant, case.id)
    ids_a = sorted(o["id"] for o in a["objects"])
    ids_b = sorted(o["id"] for o in b["objects"])
    assert ids_a == ids_b
    assert a["id"] == b["id"]


def test_include_observables_false_omits_observed_data(session, seeded_case):
    tenant, case = seeded_case
    exporter = StixExporter(session)
    bundle = exporter.export_case(tenant, case.id, include_observables=False)
    assert not any(o["type"] == "observed-data" for o in bundle["objects"])


def test_unknown_case_raises(session):
    tenant = Tenant(slug="d2", name="Demo2", is_active=True)
    session.add(tenant)
    session.flush()
    exporter = StixExporter(session)
    with pytest.raises(ValueError):
        exporter.export_case(tenant, 99999)
