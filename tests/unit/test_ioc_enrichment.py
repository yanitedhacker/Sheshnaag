"""Unit tests for the V4 IOC auto-enrichment orchestrator."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401
from app.models.malware_lab import AnalysisCase, IndicatorArtifact
from app.models.v2 import Tenant
from app.services.ioc_enrichment import (
    IocEnrichment,
    _classify_verdict,
    _consensus_score,
    _verdict_record,
)


# ---------------------------------------------------------------------------
# Connector stubs
# ---------------------------------------------------------------------------


class _StubConnector:
    """Minimal connector-shaped object for tests."""

    def __init__(
        self,
        *,
        name: str,
        healthy: bool,
        response: Any,
        raise_exc: Optional[Exception] = None,
    ) -> None:
        self.name = name
        self.healthy = healthy
        self._response = response
        self._raise = raise_exc
        self.called = False
        self.received_scope: Optional[Dict[str, Any]] = None

    def fetch(self, scope: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.called = True
        self.received_scope = scope
        if self._raise is not None:
            raise self._raise
        return list(self._response or [])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
def seeded(session):
    tenant = Tenant(slug="demo-ioc", name="Demo IOC", is_active=True)
    session.add(tenant)
    session.flush()
    case = AnalysisCase(
        tenant_id=tenant.id,
        title="Enrich Case",
        analyst_name="alice@example.com",
        specimen_ids=[],
    )
    session.add(case)
    session.flush()
    ind = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="sha256",
        value="a" * 64,
        confidence=0.5,
    )
    session.add(ind)
    session.flush()
    return tenant, case, ind


# ---------------------------------------------------------------------------
# Consensus / verdict helpers
# ---------------------------------------------------------------------------


def test_classify_verdict_from_stats():
    assert _classify_verdict({"stats": {"malicious": 10, "suspicious": 1}}) == "malicious"
    assert _classify_verdict({"stats": {"malicious": 1}}) == "suspicious"
    assert _classify_verdict({"stats": {"malicious": 0, "suspicious": 2}}) == "suspicious"
    assert _classify_verdict({"stats": {"harmless": 40}}) == "clean"


def test_classify_verdict_from_confidence():
    assert _classify_verdict({"confidence": 0.9}) == "malicious"
    assert _classify_verdict({"confidence": 0.5}) == "suspicious"
    assert _classify_verdict({"confidence": 0.1}) == "clean"
    assert _classify_verdict({}) == "unknown"


def test_consensus_score_empty_is_zero():
    assert _consensus_score([]) == 0.0


def test_consensus_score_strong_majority_malicious():
    verdicts = [
        {"verdict": "malicious", "confidence": 0.9},
        {"verdict": "malicious", "confidence": 0.8},
        {"verdict": "malicious", "confidence": 0.95},
        {"verdict": "clean", "confidence": 0.1},
    ]
    # 3 malicious + 1 clean → high consensus
    score = _consensus_score(verdicts)
    assert score >= 0.6, f"expected strong consensus, got {score}"


def test_consensus_score_single_clean_low():
    score = _consensus_score([{"verdict": "clean", "confidence": 0.1}])
    assert score == 0.0


# ---------------------------------------------------------------------------
# Fan-out behavior
# ---------------------------------------------------------------------------


def test_enrich_uses_only_healthy_connectors(session, seeded):
    _, _, indicator = seeded
    healthy = _StubConnector(
        name="healthy",
        healthy=True,
        response=[{"confidence": 0.9, "stats": {"malicious": 8}}],
    )
    sick = _StubConnector(name="sick", healthy=False, response=None)
    enricher = IocEnrichment(session, connectors=[healthy, sick])
    assert enricher.active_connectors == ["healthy"]

    result = enricher.enrich(indicator)
    assert healthy.called is True
    assert sick.called is False
    assert len(result["verdicts"]) == 1
    assert result["verdicts"][0]["source"] == "healthy"
    assert result["verdicts"][0]["verdict"] == "malicious"


def test_enrich_persists_payload(session, seeded):
    _, _, indicator = seeded
    connectors = [
        _StubConnector(
            name="vt",
            healthy=True,
            response=[{"confidence": 0.92, "stats": {"malicious": 10, "suspicious": 1}}],
        ),
        _StubConnector(
            name="otx",
            healthy=True,
            response=[{"confidence": 0.85}],
        ),
    ]
    enricher = IocEnrichment(session, connectors=connectors)
    enricher.enrich(indicator)

    refreshed = session.query(IndicatorArtifact).filter_by(id=indicator.id).one()
    payload = refreshed.payload or {}
    assert "enrichment" in payload
    assert "enrichment_consensus" in payload
    sources = {v["source"] for v in payload["enrichment"]}
    assert sources == {"vt", "otx"}
    assert 0.0 <= payload["enrichment_consensus"] <= 1.0
    assert payload["enrichment_consensus"] > 0.5


def test_enrich_handles_connector_exception(session, seeded):
    _, _, indicator = seeded
    boomer = _StubConnector(
        name="boomer",
        healthy=True,
        response=None,
        raise_exc=RuntimeError("boom"),
    )
    good = _StubConnector(
        name="good",
        healthy=True,
        response=[{"confidence": 0.7}],
    )
    enricher = IocEnrichment(session, connectors=[boomer, good])
    result = enricher.enrich(indicator)
    sources = {v["source"] for v in result["verdicts"]}
    assert "good" in sources
    assert "boomer" not in sources


def test_enrich_consensus_malicious_vs_clean(session, seeded):
    """3 malicious + 1 clean should produce a high consensus score."""
    _, _, indicator = seeded
    connectors = [
        _StubConnector(name=f"m{i}", healthy=True, response=[{"confidence": 0.9}])
        for i in range(3)
    ]
    connectors.append(
        _StubConnector(name="c1", healthy=True, response=[{"confidence": 0.05}])
    )
    enricher = IocEnrichment(session, connectors=connectors)
    result = enricher.enrich(indicator)
    # 3 malicious votes dominate
    assert result["consensus"] >= 0.5


def test_enrich_empty_connectors_yields_zero_consensus(session, seeded):
    _, _, indicator = seeded
    enricher = IocEnrichment(session, connectors=[])
    result = enricher.enrich(indicator)
    assert result["consensus"] == 0.0
    assert result["verdicts"] == []


def test_enrich_case_enriches_each_indicator(session, seeded):
    tenant, case, _ = seeded
    # Add a second indicator
    extra = IndicatorArtifact(
        tenant_id=tenant.id,
        analysis_case_id=case.id,
        indicator_kind="domain",
        value="b.invalid",
        confidence=0.4,
    )
    session.add(extra)
    session.flush()

    connector = _StubConnector(name="misp", healthy=True, response=[{"confidence": 0.8}])
    enricher = IocEnrichment(session, connectors=[connector])
    out = enricher.enrich_case(tenant, case.id)
    assert out["count"] == 2
    assert set(out["results"].keys()) == {i.id for i in session.query(IndicatorArtifact).all()}


def test_scope_shape_is_uniform(session, seeded):
    _, _, indicator = seeded
    connector = _StubConnector(name="probe", healthy=True, response=[])
    enricher = IocEnrichment(session, connectors=[connector])
    enricher.enrich(indicator)
    assert connector.received_scope is not None
    assert connector.received_scope["iocs"] == [
        {"kind": "sha256", "value": indicator.value}
    ]


def test_verdict_record_picks_highest_confidence():
    raw = [{"confidence": 0.2}, {"confidence": 0.9}, {"confidence": 0.5}]
    rec = _verdict_record("src", raw)
    assert rec is not None
    assert rec["confidence"] == 0.9
    assert rec["source"] == "src"
