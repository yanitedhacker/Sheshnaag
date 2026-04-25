"""End-to-end smoke test for the V4 autonomous-agent investigation workflow.

Walks the same path an analyst would: seed a tenant with realistic intel
(CVE + KEV + EPSS + exploit signal), drop a quarantined specimen tied to
an analysis case with indicators and findings, then drive the four real
Phase B tools in sequence, then run the autonomous agent and verify the
run survives across instances. Composition asserts make sure the data
each tool returns is consumable by the next step in a real investigation.
"""

from __future__ import annotations

from datetime import datetime, timezone

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
def seeded():
    """Build a realistic mini-corpus for one tenant and yield (session, tenant)."""

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()

    tenant = Tenant(slug="acme-soc", name="ACME SOC")
    session.add(tenant)
    session.flush()

    # Intel: CVE + enrichment fan-out
    cve = CVE(cve_id="CVE-2026-0042", description="WidgetServer authn bypass via crafted header")
    session.add(cve)
    session.flush()
    session.add(KEVEntry(cve_id="CVE-2026-0042", vendor_project="ACME", product="WidgetServer"))
    session.add(EPSSSnapshot(
        cve_id="CVE-2026-0042", score=0.71, percentile=0.94,
        scored_at=datetime.now(timezone.utc),
    ))
    session.add(ExploitSignal(
        cve_id=cve.id, signal_type="public_poc", signal_value=1.0,
        source_url="https://github.com/x/poc", confidence=0.9,
    ))

    # Malware lab: specimen + revision + analysis case + indicators + findings
    specimen = Specimen(
        tenant_id=tenant.id,
        name="widget-loader.bin",
        specimen_kind="elf",
        risk_level="critical",
        labels=["loader", "widget-server-exploit"],
    )
    session.add(specimen)
    session.flush()
    session.add(SpecimenRevision(
        specimen_id=specimen.id,
        revision_number=1,
        sha256="c0ffee" * 10 + "abcd",
        content_ref="s3://quarantine/widget-loader.bin",
        static_triage={
            "tags": ["elf", "static-linked", "embedded-c2"],
            "imports": ["__libc_start_main"],
        },
    ))
    case = AnalysisCase(
        tenant_id=tenant.id,
        title="WidgetServer intrusion 2026-W17",
        analyst_name="alice",
        specimen_ids=[specimen.id],
        status="investigating",
    )
    session.add(case)
    session.flush()
    session.add_all([
        IndicatorArtifact(
            tenant_id=tenant.id,
            analysis_case_id=case.id,
            indicator_kind="domain",
            value="c2.evil.example.com",
            confidence=0.92,
        ),
        IndicatorArtifact(
            tenant_id=tenant.id,
            analysis_case_id=case.id,
            indicator_kind="ipv4",
            value="198.51.100.42",
            confidence=0.85,
        ),
        IndicatorArtifact(
            tenant_id=tenant.id,
            analysis_case_id=case.id,
            indicator_kind="sha256",
            value="c0ffee" * 10 + "abcd",
            confidence=1.0,
        ),
        BehaviorFinding(
            tenant_id=tenant.id,
            analysis_case_id=case.id,
            finding_type="network_c2",
            title="Beacon to c2.evil.example.com on TCP/443 every 60s",
            severity="high",
            confidence=0.88,
            payload={"attack_techniques": [{"technique_id": "T1071.001"}]},
        ),
    ])
    session.commit()

    try:
        yield session, tenant, specimen, case
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def _ctx(session, tenant):
    return {"session": session, "tenant_id": tenant.id, "actor": "alice"}


def test_e2e_analyst_investigation_flow(seeded):
    """The four real Phase B tools chain into a coherent investigation."""

    session, tenant, specimen, case = seeded
    ctx = _ctx(session, tenant)

    # 1. Triage the specimen — agent's first move when handed a binary.
    triage = get_tool("fetch_specimen_triage").callable(specimen_id=specimen.id, _context=ctx)
    assert triage["triage"]["sha256"] == "c0ffee" * 10 + "abcd"
    sha = triage["triage"]["sha256"]
    assert "loader" in triage["triage"]["labels"]

    # 2. Pivot on the sha256 — should land on the same case + neighbors.
    pivot = get_tool("pivot_ioc").callable(indicator_value=sha, _context=ctx)
    assert pivot["case_count"] == 1
    case_neighbors = [n for n in pivot["neighbors"] if n["kind"] == "case"]
    indicator_neighbors = [n for n in pivot["neighbors"] if n["kind"] == "indicator"]
    finding_neighbors = [n for n in pivot["neighbors"] if n["kind"] == "finding"]
    assert any(n["id"] == case.id for n in case_neighbors)
    assert any(n["value"] == "c2.evil.example.com" for n in indicator_neighbors)
    assert any("Beacon" in n["title"] for n in finding_neighbors)

    # 3. Enrich the related CVE — analyst correlates malware to known intel.
    enrich = get_tool("query_intel_feed").callable(
        source="local", iocs=["CVE-2026-0042", "c2.evil.example.com"], _context=ctx,
    )
    cve_row = next(e for e in enrich["enrichment"] if e["ioc"] == "CVE-2026-0042")
    assert cve_row["kev"]["product"] == "WidgetServer"
    assert cve_row["epss"]["score"] == pytest.approx(0.71)
    assert len(cve_row["exploit_signals"]) == 1
    domain_row = next(e for e in enrich["enrichment"] if e["ioc"] == "c2.evil.example.com")
    assert domain_row["note"] == "no_local_enrichment_for_non_cve"

    # 4. Knowledge corpus query — cold corpus returns empty, but the call
    #    must succeed (proves the wiring, even when nothing is indexed yet).
    kq = get_tool("query_knowledge").callable(
        query="WidgetServer authentication bypass remediation", k=3, _context=ctx,
    )
    assert kq["query"].startswith("WidgetServer")
    assert isinstance(kq["hits"], list)
    assert "error" not in kq


def test_e2e_agent_run_persists_and_replays(seeded):
    """An autonomous-agent run anchored on a real case is durable and listable."""

    session, tenant, specimen, case = seeded

    # Producer instance runs against the seeded case.
    producer = AutonomousAgent(session)
    run = producer.run(
        tenant,
        goal="Summarise the WidgetServer incident and ATT&CK posture.",
        actor="alice",
        case_id=case.id,
        max_steps=4,
    )
    assert run.run_id
    # Non-denied path means the deterministic workflow did at least the
    # case-summary + ATT&CK + synthesis steps.
    if run.status == "completed":
        assert any(s.tool == "summarise_case" for s in run.steps)
        assert any(s.tool == "synthesise" for s in run.steps)

    # Consumer instance: simulates a different process/replica reading the
    # run history. Must not depend on producer's in-memory cache.
    consumer = AutonomousAgent(session)
    listed = consumer.list_runs(tenant=tenant)
    assert any(r["run_id"] == run.run_id for r in listed)

    # Direct DB inspection — this is the durability assertion that matters
    # for the "in-memory only" gap the user flagged.
    row = (
        session.query(AutonomousAgentRun)
        .filter(AutonomousAgentRun.run_id == run.run_id)
        .first()
    )
    assert row is not None
    assert row.tenant_id == tenant.id
    assert row.case_id == case.id
    assert row.actor == "alice"
    assert row.status in {"completed", "denied"}
    assert isinstance(row.steps, list)


def test_e2e_cross_tenant_isolation_is_preserved(seeded):
    """Phase B tools must not leak across tenants."""

    session, tenant_a, specimen_a, _ = seeded
    other = Tenant(slug="other-soc", name="Other SOC")
    session.add(other)
    session.commit()

    ctx_other = _ctx(session, other)

    # Triage of A's specimen from B's context => 404
    triage = get_tool("fetch_specimen_triage").callable(specimen_id=specimen_a.id, _context=ctx_other)
    assert triage.get("error") == "specimen_not_found"

    # Pivot on A's known IOC from B's context => no neighbors
    pivot = get_tool("pivot_ioc").callable(indicator_value="c2.evil.example.com", _context=ctx_other)
    assert pivot["neighbors"] == []
    assert pivot.get("note") == "indicator_not_found"

    # Agent run history is tenant-scoped
    AutonomousAgent(session).run(tenant_a, goal="x", actor="alice")
    listed_other = AutonomousAgent(session).list_runs(tenant=other)
    assert listed_other == []
