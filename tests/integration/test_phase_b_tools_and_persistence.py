"""Phase B integration tests: real tool implementations + durable agent runs.

Closes the verification gap left by the Phase A stub registry: every tool
that was previously a hard-coded shape now actually queries the DB, and the
autonomous agent's run history survives across instances of the service.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.cve import CVE
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
    SpecimenRevision,
)
from app.models.sheshnaag import AutonomousAgentRun, ExploitSignal
from app.models.v2 import EPSSSnapshot, KEVEntry, Tenant
from app.services.ai_tools_registry import get_tool
from app.services.autonomous_agent import AutonomousAgent


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def tenant(db_session):
    t = Tenant(slug="phase-b", name="Phase B Test")
    db_session.add(t)
    db_session.commit()
    return t


# ---------------------------------------------------------------------------
# T2a — fetch_specimen_triage
# ---------------------------------------------------------------------------


def test_fetch_specimen_triage_returns_real_revision(db_session, tenant):
    spec = Specimen(
        tenant_id=tenant.id,
        name="evil.exe",
        specimen_kind="pe",
        risk_level="critical",
        labels=["worm", "ransomware"],
    )
    db_session.add(spec)
    db_session.flush()
    rev = SpecimenRevision(
        specimen_id=spec.id,
        revision_number=1,
        sha256="a" * 64,
        content_ref="s3://quarantine/evil.exe",
        static_triage={"tags": ["pe", "packed"], "imports": ["kernel32!CreateFileW"]},
    )
    db_session.add(rev)
    db_session.commit()

    tool = get_tool("fetch_specimen_triage")
    out = tool.callable(
        specimen_id=spec.id,
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    assert out["triage"]["sha256"] == "a" * 64
    assert out["triage"]["kind"] == "pe"
    assert "packed" in out["triage"]["tags"]
    assert out["triage"]["revision_number"] == 1


def test_fetch_specimen_triage_blocks_cross_tenant(db_session, tenant):
    other = Tenant(slug="other", name="Other")
    db_session.add(other)
    db_session.flush()
    spec = Specimen(tenant_id=other.id, name="x", specimen_kind="file")
    db_session.add(spec)
    db_session.commit()
    out = get_tool("fetch_specimen_triage").callable(
        specimen_id=spec.id,
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    assert out.get("error") == "specimen_not_found"


# ---------------------------------------------------------------------------
# T2b — pivot_ioc
# ---------------------------------------------------------------------------


def test_pivot_ioc_returns_siblings_and_findings(db_session, tenant):
    case = AnalysisCase(tenant_id=tenant.id, title="ABC.exe", analyst_name="alice")
    db_session.add(case)
    db_session.flush()
    seed = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="domain",
        value="evil.example.com",
    )
    sibling = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="ipv4",
        value="1.2.3.4",
    )
    finding = BehaviorFinding(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        finding_type="network_c2",
        title="C2 beacon",
        severity="high",
    )
    db_session.add_all([seed, sibling, finding])
    db_session.commit()

    out = get_tool("pivot_ioc").callable(
        indicator_value="evil.example.com",
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    kinds = {n["kind"] for n in out["neighbors"]}
    assert "indicator" in kinds
    assert "finding" in kinds
    assert "case" in kinds
    assert out["case_count"] == 1


def test_pivot_ioc_unknown_value(db_session, tenant):
    out = get_tool("pivot_ioc").callable(
        indicator_value="nope.invalid",
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    assert out["neighbors"] == []
    assert out.get("note") == "indicator_not_found"


# ---------------------------------------------------------------------------
# T2c — query_knowledge (graceful degrade — no docs indexed)
# ---------------------------------------------------------------------------


def test_query_knowledge_returns_empty_on_cold_corpus(db_session, tenant):
    out = get_tool("query_knowledge").callable(
        query="lateral movement via WMI",
        k=5,
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    # No documents seeded => empty hit list, but the call itself ran
    assert out["query"] == "lateral movement via WMI"
    assert out["k"] == 5
    assert isinstance(out["hits"], list)
    assert "error" not in out, f"unexpected error path: {out}"


# ---------------------------------------------------------------------------
# T2d — query_intel_feed (CVE / KEV / EPSS / ExploitSignal)
# ---------------------------------------------------------------------------


def test_query_intel_feed_joins_cve_kev_epss(db_session, tenant):
    cve = CVE(cve_id="CVE-2026-9999", description="test cve")
    db_session.add(cve)
    db_session.flush()  # need cve.id for ExploitSignal.cve_id (integer FK)
    kev = KEVEntry(
        cve_id="CVE-2026-9999",
        vendor_project="ACME",
        product="WidgetServer",
        short_description="RCE via crafted header",
    )
    from datetime import datetime, timezone
    epss = EPSSSnapshot(
        cve_id="CVE-2026-9999",
        score=0.82,
        percentile=0.97,
        scored_at=datetime.now(timezone.utc),
    )
    signal = ExploitSignal(
        cve_id=cve.id,
        signal_type="poc_published",
        signal_value=1.0,
        source_url="github.com/researcher/poc",
        confidence=0.9,
    )
    db_session.add_all([kev, epss, signal])
    db_session.commit()

    out = get_tool("query_intel_feed").callable(
        source="local",
        iocs=["CVE-2026-9999", "8.8.8.8"],
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    enrich = {e["ioc"]: e for e in out["enrichment"]}
    assert enrich["CVE-2026-9999"]["cve"]["cve_id"] == "CVE-2026-9999"
    assert enrich["CVE-2026-9999"]["kev"]["product"] == "WidgetServer"
    assert enrich["CVE-2026-9999"]["epss"]["score"] == pytest.approx(0.82)
    assert len(enrich["CVE-2026-9999"]["exploit_signals"]) == 1
    assert enrich["8.8.8.8"]["note"] == "no_local_enrichment_for_non_cve"


# ---------------------------------------------------------------------------
# T2e — run_yara_scan (rules + match)
# ---------------------------------------------------------------------------


def test_run_yara_scan_matches_seeded_rule(db_session, tenant, tmp_path, monkeypatch):
    yara = pytest.importorskip("yara")  # noqa: F841

    # Seed a rule + a target file the rule will match.
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test_pack.yar").write_text(
        'rule TestPack { strings: $s = "MARKER_42" condition: $s }'
    )
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    target = quarantine / "evil.bin"
    target.write_bytes(b"benign prefix \xde\xad\xbe\xef MARKER_42 trailing")

    spec = Specimen(tenant_id=tenant.id, name="evil.bin", specimen_kind="binary")
    db_session.add(spec)
    db_session.flush()
    rev = SpecimenRevision(
        specimen_id=spec.id,
        revision_number=1,
        sha256="b" * 64,
        content_ref=str(target),
        quarantine_path=str(target),
    )
    db_session.add(rev)
    db_session.commit()

    monkeypatch.setenv("SHESHNAAG_YARA_RULES_DIR", str(rules_dir))
    out = get_tool("run_yara_scan").callable(
        ruleset_id="test_pack",
        scope={"specimen_id": spec.id},
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    assert out.get("error") is None, out
    assert any(m["rule"] == "TestPack" for m in out["matches"])


def test_run_yara_scan_rejects_path_outside_quarantine_root(db_session, tenant, tmp_path, monkeypatch):
    pytest.importorskip("yara")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "any.yar").write_text("rule R { condition: true }")
    monkeypatch.setenv("SHESHNAAG_YARA_RULES_DIR", str(rules_dir))
    monkeypatch.setenv("SHESHNAAG_QUARANTINE_ROOT", str(tmp_path / "ok"))
    (tmp_path / "ok").mkdir()

    out = get_tool("run_yara_scan").callable(
        ruleset_id="any",
        scope={"path": "/etc/passwd"},
        _context={"session": db_session, "tenant_id": tenant.id, "actor": "tester"},
    )
    assert out["error"] == "scope_path_not_in_quarantine_root"


# ---------------------------------------------------------------------------
# T1 — durable autonomous-agent runs
# ---------------------------------------------------------------------------


def test_autonomous_agent_persists_runs_across_instances(db_session, tenant):
    agent_a = AutonomousAgent(db_session)
    run = agent_a.run(tenant, goal="Summarise active findings", actor="tester")
    assert run.run_id

    # New AutonomousAgent on the same DB sees the prior run
    agent_b = AutonomousAgent(db_session)
    listed = agent_b.list_runs(tenant=tenant)
    assert any(r["run_id"] == run.run_id for r in listed)
    persisted = (
        db_session.query(AutonomousAgentRun)
        .filter(AutonomousAgentRun.run_id == run.run_id)
        .first()
    )
    assert persisted is not None
    assert persisted.actor == "tester"
    assert persisted.goal.startswith("Summarise")
    # Run may be denied by the capability gate when no authorization artifact
    # is seeded; that's a valid persisted shape (status="denied", steps=[]).
    assert persisted.status in {"completed", "denied"}
    assert isinstance(persisted.steps, list)
