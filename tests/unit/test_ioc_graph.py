"""Unit tests for the V4 Phase C slice-4 IOC pivot graph extension.

Covers :meth:`ExposureGraphService.rebuild_ioc_graph`,
:meth:`ExposureGraphService.ioc_neighborhood`, and
:meth:`ExposureGraphService.attack_paths_for_ioc`.
"""

from __future__ import annotations

from typing import Tuple

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401  # register all model tables
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
from app.models.v2 import ExposureGraphEdge, ExposureGraphNode, Tenant
from app.services.graph_service import (
    IOC_EDGE_KINDS,
    ExposureGraphService,
)


@pytest.fixture()
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = TestingSession()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


def _make_tenant(session: Session, *, slug: str = "acme") -> Tenant:
    tenant = Tenant(slug=slug, name=f"{slug.title()} Tenant", is_demo=False)
    session.add(tenant)
    session.flush()
    return tenant


def _make_case(
    session: Session,
    tenant: Tenant,
    *,
    title: str,
    specimen_ids=None,
) -> AnalysisCase:
    case = AnalysisCase(
        tenant_id=tenant.id,
        title=title,
        analyst_name="unit-test",
        specimen_ids=specimen_ids or [],
    )
    session.add(case)
    session.flush()
    return case


def _make_specimen(session: Session, tenant: Tenant, *, name: str) -> Specimen:
    spec = Specimen(tenant_id=tenant.id, name=name)
    session.add(spec)
    session.flush()
    return spec


def _make_finding(
    session: Session,
    tenant: Tenant,
    case: AnalysisCase,
    *,
    title: str,
    confidence: float,
    severity: str = "medium",
) -> BehaviorFinding:
    finding = BehaviorFinding(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        finding_type="network.c2",
        title=title,
        severity=severity,
        confidence=confidence,
    )
    session.add(finding)
    session.flush()
    return finding


def _make_indicator(
    session: Session,
    tenant: Tenant,
    case: AnalysisCase,
    *,
    kind: str,
    value: str,
    payload: dict | None = None,
    confidence: float = 0.8,
) -> IndicatorArtifact:
    indicator = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind=kind,
        value=value,
        confidence=confidence,
        payload=payload or {},
    )
    session.add(indicator)
    session.flush()
    return indicator


def _edge_types(session: Session, tenant: Tenant) -> list[Tuple[str, str, str, float]]:
    # Build a (from_key, edge_type, to_key, weight) view for every edge.
    node_by_id = {
        node.id: node
        for node in session.query(ExposureGraphNode)
        .filter(ExposureGraphNode.tenant_id == tenant.id)
        .all()
    }
    edges = (
        session.query(ExposureGraphEdge)
        .filter(ExposureGraphEdge.tenant_id == tenant.id)
        .all()
    )
    out: list[Tuple[str, str, str, float]] = []
    for edge in edges:
        from_node = node_by_id.get(edge.from_node_id)
        to_node = node_by_id.get(edge.to_node_id)
        out.append(
            (
                from_node.node_key if from_node else "?",
                edge.edge_type,
                to_node.node_key if to_node else "?",
                float(edge.weight or 0.0),
            )
        )
    return out


def test_rebuild_ioc_graph_creates_expected_edges(session: Session) -> None:
    tenant = _make_tenant(session)

    specimen = _make_specimen(session, tenant, name="sample.bin")
    case = _make_case(session, tenant, title="Case A", specimen_ids=[specimen.id])

    f1 = _make_finding(session, tenant, case, title="C2 beacon", confidence=0.85)
    f2 = _make_finding(
        session, tenant, case, title="Persistence key", confidence=0.4
    )

    cve = CVE(cve_id="CVE-2025-00001", description="demo cve")
    session.add(cve)
    session.flush()

    ind_ip = _make_indicator(
        session,
        tenant,
        case,
        kind="ipv4",
        value="203.0.113.7",
        payload={
            "finding_ids": [f1.id, f2.id],
            "cve_ids": ["CVE-2025-00001"],
        },
    )
    ind_hash = _make_indicator(
        session,
        tenant,
        case,
        kind="sha256",
        value="a" * 64,
        payload={"finding_ids": [f1.id]},
    )

    service = ExposureGraphService(session)
    summary = service.rebuild_ioc_graph(tenant)
    session.flush()

    assert summary["nodes"] == 2  # two indicator nodes
    # Two ioc_to_finding from ip (to f1, f2), one from hash (to f1) = 3
    # Two ioc_to_specimen (one per indicator) via case.specimen_ids = 2
    # One ioc_to_cve from ip = 1
    # Co-occurrence pair ip<->hash shares exactly one case, so 2 directional rows.
    # Total IOC edges: 3 + 2 + 1 + 2 = 8
    assert summary["edges"] == 8

    edge_view = _edge_types(session, tenant)
    ioc_rows = [row for row in edge_view if row[1] in IOC_EDGE_KINDS]
    assert len(ioc_rows) == 8

    # ioc_to_finding weights must equal finding.confidence.
    finding_edges = {
        (row[0], row[2]): row[3] for row in ioc_rows if row[1] == "ioc_to_finding"
    }
    assert finding_edges[(f"indicator:{ind_ip.id}", f"finding:{f1.id}")] == pytest.approx(0.85)
    assert finding_edges[(f"indicator:{ind_ip.id}", f"finding:{f2.id}")] == pytest.approx(0.4)
    assert finding_edges[(f"indicator:{ind_hash.id}", f"finding:{f1.id}")] == pytest.approx(0.85)

    # ioc_to_specimen weights are 0.9.
    specimen_edges = [row for row in ioc_rows if row[1] == "ioc_to_specimen"]
    assert len(specimen_edges) == 2
    for row in specimen_edges:
        assert row[3] == pytest.approx(0.9)
        assert row[2] == f"specimen:{specimen.id}"

    # ioc_to_cve weights are 0.5.
    cve_edges = [row for row in ioc_rows if row[1] == "ioc_to_cve"]
    assert len(cve_edges) == 1
    assert cve_edges[0][0] == f"indicator:{ind_ip.id}"
    assert cve_edges[0][2] == f"cve:{cve.id}"
    assert cve_edges[0][3] == pytest.approx(0.5)

    # Co-occurrence edges: shared_cases = 1, max(case_count) = 1 → weight 1.0.
    co_edges = [row for row in ioc_rows if row[1] == "ioc_cooccurs_with"]
    assert len(co_edges) == 2  # symmetric pair emitted in both directions
    for row in co_edges:
        assert row[3] == pytest.approx(1.0)


def test_ioc_neighborhood_depth_two(session: Session) -> None:
    tenant = _make_tenant(session, slug="depth-test")
    specimen = _make_specimen(session, tenant, name="variant.bin")
    case = _make_case(session, tenant, title="Depth Case", specimen_ids=[specimen.id])

    finding = _make_finding(session, tenant, case, title="Outbound C2", confidence=0.9)

    ind_ip = _make_indicator(
        session,
        tenant,
        case,
        kind="ipv4",
        value="198.51.100.42",
        payload={"finding_ids": [finding.id]},
    )
    ind_hash = _make_indicator(
        session,
        tenant,
        case,
        kind="sha256",
        value="b" * 64,
        payload={"finding_ids": [finding.id]},
    )

    service = ExposureGraphService(session)
    service.rebuild_ioc_graph(tenant)
    session.flush()

    slice_depth1 = service.ioc_neighborhood(
        tenant, indicator_value="198.51.100.42", depth=1
    )
    keys_depth1 = {node["node_key"] for node in slice_depth1["nodes"]}
    # depth=1 from the IP: its finding, its specimen, and the co-occurring hash.
    assert f"indicator:{ind_ip.id}" in keys_depth1
    assert f"finding:{finding.id}" in keys_depth1
    assert f"specimen:{specimen.id}" in keys_depth1
    assert f"indicator:{ind_hash.id}" in keys_depth1

    slice_depth2 = service.ioc_neighborhood(
        tenant, indicator_value="198.51.100.42", depth=2
    )
    keys_depth2 = {node["node_key"] for node in slice_depth2["nodes"]}
    assert keys_depth1.issubset(keys_depth2)
    # At depth 2 we should still reach the hash's own specimen edge if any
    # extra hops exist. In this seed, depth 2 adds nothing new beyond depth 1
    # because every node is already one hop from ind_ip; but at minimum we
    # must not regress.
    assert len(slice_depth2["nodes"]) >= len(slice_depth1["nodes"])

    # Unknown indicator returns empty slice gracefully.
    empty = service.ioc_neighborhood(
        tenant, indicator_value="does-not-exist", depth=2
    )
    assert empty["nodes"] == []
    assert empty["edges"] == []
    assert empty["root_node_ids"] == []


def test_ioc_cooccurrence_weight_formula(session: Session) -> None:
    """Co-occurrence weight is ``shared_cases / max(total_cases)``.

    Indicators are identified by their ``(kind, value)`` pair across rows,
    so the same logical IOC appearing in multiple cases aggregates its
    case set.
    """

    tenant = _make_tenant(session, slug="cooccur")

    case_a = _make_case(session, tenant, title="Case A")
    case_b = _make_case(session, tenant, title="Case B")

    # Scenario 1 — two logical IOCs X and Y sharing exactly one of two cases:
    #
    #   X in A, X in B     → identity X, cases = {A, B}
    #   Y in A             → identity Y, cases = {A}
    #
    # shared = |{A}| = 1,  max(|{A,B}|, |{A}|) = 2  → weight 0.5.
    _make_indicator(session, tenant, case_a, kind="domain", value="x.example")
    _make_indicator(session, tenant, case_b, kind="domain", value="x.example")
    _make_indicator(session, tenant, case_a, kind="domain", value="y.example")

    service = ExposureGraphService(session)
    service.rebuild_ioc_graph(tenant)
    session.flush()

    co_edges = (
        session.query(ExposureGraphEdge)
        .filter(
            ExposureGraphEdge.tenant_id == tenant.id,
            ExposureGraphEdge.edge_type == "ioc_cooccurs_with",
        )
        .all()
    )
    # Exactly one logical pair (X, Y) → two symmetric directed edges.
    assert len(co_edges) == 2
    for edge in co_edges:
        assert float(edge.weight) == pytest.approx(0.5)

    # Scenario 2 — give Y a second case so shared=1, max=2 still (unchanged).
    # Then give X a third case so max=3, shared=1 → weight 1/3.
    case_c = _make_case(session, tenant, title="Case C")
    _make_indicator(session, tenant, case_c, kind="domain", value="y.example")
    # Y now appears in {A, C}; X still appears in {A, B}; shared = {A} = 1.
    # max(2, 2) = 2 → weight 0.5 still.
    service.rebuild_ioc_graph(tenant)
    session.flush()
    co_edges = (
        session.query(ExposureGraphEdge)
        .filter(
            ExposureGraphEdge.tenant_id == tenant.id,
            ExposureGraphEdge.edge_type == "ioc_cooccurs_with",
        )
        .all()
    )
    assert co_edges, "expected at least one co-occurrence edge"
    for edge in co_edges:
        assert float(edge.weight) == pytest.approx(0.5)

    # Scenario 3 — add a fourth case D, put X in it. Now X cases = {A, B, D}
    # (3), Y cases = {A, C} (2), shared = {A} = 1 → weight 1 / max(3, 2) = 1/3.
    case_d = _make_case(session, tenant, title="Case D")
    _make_indicator(session, tenant, case_d, kind="domain", value="x.example")
    service.rebuild_ioc_graph(tenant)
    session.flush()
    co_edges = (
        session.query(ExposureGraphEdge)
        .filter(
            ExposureGraphEdge.tenant_id == tenant.id,
            ExposureGraphEdge.edge_type == "ioc_cooccurs_with",
        )
        .all()
    )
    assert co_edges
    for edge in co_edges:
        assert float(edge.weight) == pytest.approx(1.0 / 3.0)


def test_attack_paths_for_ioc_returns_top_k(session: Session) -> None:
    tenant = _make_tenant(session, slug="paths")

    # Two CVEs — the search targets CVE nodes directly.
    cve_a = CVE(cve_id="CVE-2025-10001", description="", exploit_available=True)
    cve_b = CVE(cve_id="CVE-2025-10002", description="", exploit_available=False)
    session.add_all([cve_a, cve_b])
    session.flush()

    specimen = _make_specimen(session, tenant, name="paths.bin")
    case = _make_case(
        session, tenant, title="Paths Case", specimen_ids=[specimen.id]
    )
    f = _make_finding(session, tenant, case, title="Impact", confidence=0.7)

    _make_indicator(
        session,
        tenant,
        case,
        kind="ipv4",
        value="192.0.2.55",
        payload={
            "cve_ids": ["CVE-2025-10001", "CVE-2025-10002"],
            "finding_ids": [f.id],
        },
    )

    service = ExposureGraphService(session)
    service.rebuild_ioc_graph(tenant)
    session.flush()

    # top_k respected — ask for 1, expect exactly 1 path.
    result = service.attack_paths_for_ioc(
        tenant, indicator_value="192.0.2.55", top_k=1
    )
    assert len(result["paths"]) == 1
    assert result["paths"][0]["summary"].startswith("192.0.2.55 -> ")

    # Asking for up to 5 should return two CVE-terminating paths (at most).
    bigger = service.attack_paths_for_ioc(
        tenant, indicator_value="192.0.2.55", top_k=5
    )
    assert 1 <= len(bigger["paths"]) <= 5
    # Scores must be sorted descending.
    scores = [path["score"] for path in bigger["paths"]]
    assert scores == sorted(scores, reverse=True)
    # Every returned path must end at a CVE node.
    for path in bigger["paths"]:
        assert path["labels"][-1].startswith("CVE-")

    # Unknown indicator — empty paths, no error.
    empty = service.attack_paths_for_ioc(
        tenant, indicator_value="unknown", top_k=3
    )
    assert empty["paths"] == []

    # Argument validation.
    with pytest.raises(ValueError):
        service.attack_paths_for_ioc(tenant, indicator_value="", top_k=3)
    with pytest.raises(ValueError):
        service.attack_paths_for_ioc(tenant, indicator_value="x", top_k=0)
