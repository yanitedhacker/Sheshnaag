"""Tier 4 integration tests: behavior similarity + variant diff."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import similarity_router
from app.core.database import Base, get_sync_session
from app.models.embeddings import SpecimenBehaviorEmbedding
from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
from app.models.v2 import Tenant
from app.services.behavior_similarity_service import BehaviorSimilarityService


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
    app.include_router(similarity_router)
    app.dependency_overrides[get_sync_session] = _get_session
    yield app, SessionLocal
    Base.metadata.drop_all(bind=engine)


def _seed(session, *, tenant_slug, specs):
    """Seed a tenant with a list of specimens described by feature dicts."""

    tenant = Tenant(slug=tenant_slug, name=tenant_slug)
    session.add(tenant)
    session.flush()

    created = []
    for spec_def in specs:
        spec = Specimen(
            tenant_id=tenant.id,
            name=spec_def["name"],
            specimen_kind=spec_def.get("kind", "elf"),
            labels=spec_def.get("labels", []),
        )
        session.add(spec)
        session.flush()
        case = AnalysisCase(
            tenant_id=tenant.id,
            title=f"Case for {spec.name}",
            analyst_name="alice",
            specimen_ids=[spec.id],
        )
        session.add(case)
        session.flush()
        for ind in spec_def.get("indicators", []):
            session.add(IndicatorArtifact(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                indicator_kind=ind["kind"],
                value=ind["value"],
                confidence=0.9,
            ))
        for f in spec_def.get("findings", []):
            session.add(BehaviorFinding(
                tenant_id=tenant.id,
                analysis_case_id=case.id,
                finding_type=f["type"],
                title=f["title"],
                severity=f.get("severity", "medium"),
                payload={
                    "attack_techniques": [
                        {"technique_id": tid} for tid in f.get("techniques", [])
                    ]
                },
            ))
        created.append(spec)
    session.commit()
    return tenant, created


# ---------------------------------------------------------------------------
# Service-level
# ---------------------------------------------------------------------------


def test_embed_specimen_persists_and_is_idempotent(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [spec] = _seed(s, tenant_slug="acme-1", specs=[{
            "name": "loader.bin",
            "kind": "elf",
            "labels": ["loader"],
            "indicators": [{"kind": "domain", "value": "c2.evil.example.com"}],
            "findings": [{"type": "network_c2", "title": "Beacon", "techniques": ["T1071.001"]}],
        }])
        svc = BehaviorSimilarityService(s)
        first = svc.embed_specimen(tenant, specimen_id=spec.id)
        assert first["status"] == "stored"
        second = svc.embed_specimen(tenant, specimen_id=spec.id)
        assert second["status"] == "unchanged"
        assert first["feature_digest"] == second["feature_digest"]

        rows = s.query(SpecimenBehaviorEmbedding).filter(
            SpecimenBehaviorEmbedding.specimen_id == spec.id
        ).all()
        # Idempotent => still exactly one row
        assert len(rows) == 1
        assert rows[0].embedding is not None and len(rows[0].embedding) == 1024


def test_find_similar_ranks_overlap_higher_than_disjoint(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [anchor, near, far] = _seed(s, tenant_slug="acme-2", specs=[
            {  # anchor
                "name": "anchor.bin",
                "labels": ["loader", "ransomware"],
                "indicators": [
                    {"kind": "domain", "value": "c2.evil.example.com"},
                    {"kind": "ipv4", "value": "198.51.100.42"},
                ],
                "findings": [
                    {"type": "network_c2", "title": "Beacon", "techniques": ["T1071.001"]},
                    {"type": "persistence", "title": "Cron persistence", "techniques": ["T1053.003"]},
                ],
            },
            {  # near — shares two techniques + one IOC
                "name": "near.bin",
                "labels": ["loader"],
                "indicators": [
                    {"kind": "domain", "value": "c2.evil.example.com"},
                    {"kind": "ipv4", "value": "203.0.113.7"},
                ],
                "findings": [
                    {"type": "network_c2", "title": "Beacon variant", "techniques": ["T1071.001"]},
                    {"type": "persistence", "title": "Cron variant", "techniques": ["T1053.003"]},
                ],
            },
            {  # far — completely different family
                "name": "far.bin",
                "labels": ["dropper"],
                "indicators": [{"kind": "url", "value": "https://x.test/payload"}],
                "findings": [
                    {"type": "credential_theft", "title": "LSASS read", "techniques": ["T1003.001"]}
                ],
            },
        ])
        svc = BehaviorSimilarityService(s)
        # Embed all three explicitly so results are deterministic
        for spec in (anchor, near, far):
            svc.embed_specimen(tenant, specimen_id=spec.id)

        out = svc.find_similar(tenant, specimen_id=anchor.id, top_k=10)
        ids = [m["specimen_id"] for m in out["matches"]]
        scores = {m["specimen_id"]: m["score"] for m in out["matches"]}
        assert near.id in ids and far.id in ids
        # Near must score higher than far — that's the contract analysts care about
        assert scores[near.id] > scores[far.id]


def test_variant_diff_breaks_down_features_and_returns_cosine(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [a, b] = _seed(s, tenant_slug="acme-3", specs=[
            {
                "name": "a.bin",
                "labels": ["loader", "ransomware"],
                "indicators": [
                    {"kind": "domain", "value": "shared.example.com"},
                    {"kind": "ipv4", "value": "10.0.0.1"},
                ],
                "findings": [
                    {"type": "network_c2", "title": "Beacon", "techniques": ["T1071.001"]},
                    {"type": "persistence", "title": "Cron", "techniques": ["T1053.003"]},
                ],
            },
            {
                "name": "b.bin",
                "labels": ["loader"],
                "indicators": [
                    {"kind": "domain", "value": "shared.example.com"},
                    {"kind": "ipv4", "value": "10.0.0.2"},
                ],
                "findings": [
                    {"type": "network_c2", "title": "Beacon", "techniques": ["T1071.001"]},
                    {"type": "credential_theft", "title": "LSASS", "techniques": ["T1003.001"]},
                ],
            },
        ])
        svc = BehaviorSimilarityService(s)
        diff = svc.variant_diff(tenant, specimen_id_a=a.id, specimen_id_b=b.id)

        assert diff["specimen_a"]["id"] == a.id
        assert diff["specimen_b"]["id"] == b.id
        # Cosine score is in [0, 1] range here (non-negative hash bow projections)
        assert 0.0 <= diff["cosine_similarity"] <= 1.0

        labels_diff = diff["feature_diff"]["labels"]
        assert "loader" in labels_diff["shared"]
        assert "ransomware" in labels_diff["only_a"]
        assert labels_diff["only_b"] == []

        ioc_diff = diff["feature_diff"]["indicator_values"]
        assert "shared.example.com" in ioc_diff["shared"]
        assert "10.0.0.1" in ioc_diff["only_a"]
        assert "10.0.0.2" in ioc_diff["only_b"]

        attck_diff = diff["feature_diff"]["attack_techniques"]
        assert "T1071.001" in attck_diff["shared"]
        assert "T1053.003" in attck_diff["only_a"]
        assert "T1003.001" in attck_diff["only_b"]


def test_variant_diff_rejects_same_specimen(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [spec] = _seed(s, tenant_slug="acme-4", specs=[
            {"name": "x.bin", "indicators": [], "findings": []}
        ])
        svc = BehaviorSimilarityService(s)
        with pytest.raises(ValueError, match="specimens_must_differ"):
            svc.variant_diff(tenant, specimen_id_a=spec.id, specimen_id_b=spec.id)


def test_cross_tenant_isolation(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant_a, [spec_a] = _seed(s, tenant_slug="acme-5", specs=[
            {"name": "a.bin", "indicators": [{"kind": "domain", "value": "x.com"}], "findings": []}
        ])
        tenant_b, [spec_b] = _seed(s, tenant_slug="other-5", specs=[
            {"name": "b.bin", "indicators": [{"kind": "domain", "value": "x.com"}], "findings": []}
        ])
        svc = BehaviorSimilarityService(s)
        svc.embed_specimen(tenant_a, specimen_id=spec_a.id)
        svc.embed_specimen(tenant_b, specimen_id=spec_b.id)

        out_a = svc.find_similar(tenant_a, specimen_id=spec_a.id)
        ids = {m["specimen_id"] for m in out_a["matches"]}
        assert spec_b.id not in ids  # cross-tenant must not appear

        # Diff across tenants must 404 (the "other" specimen is not visible)
        with pytest.raises(ValueError, match="specimen_not_found"):
            svc.variant_diff(tenant_a, specimen_id_a=spec_a.id, specimen_id_b=spec_b.id)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_similarity_routes_embed_then_search(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [spec_a, spec_b] = _seed(s, tenant_slug="acme-6", specs=[
            {"name": "a", "indicators": [{"kind": "domain", "value": "z.com"}], "findings": []},
            {"name": "b", "indicators": [{"kind": "domain", "value": "z.com"}], "findings": []},
        ])
        tenant_id, sid_a, sid_b = tenant.id, spec_a.id, spec_b.id

    client = TestClient(app)

    r = client.post(f"/api/v4/specimens/{sid_a}/embed", params={"tenant_id": tenant_id})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "stored"

    r = client.post(f"/api/v4/specimens/{sid_b}/embed", params={"tenant_id": tenant_id})
    assert r.status_code == 200, r.text

    r = client.get(f"/api/v4/specimens/{sid_a}/similar", params={"tenant_id": tenant_id, "top_k": 5})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["specimen_id"] == sid_a
    assert any(m["specimen_id"] == sid_b for m in body["matches"])


def test_similarity_route_404_unknown_specimen(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, _ = _seed(s, tenant_slug="acme-7", specs=[
            {"name": "x", "indicators": [], "findings": []}
        ])
        tenant_id = tenant.id
    client = TestClient(app)
    r = client.get("/api/v4/specimens/999999/similar", params={"tenant_id": tenant_id})
    assert r.status_code == 404


def test_variant_diff_route(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [a, b] = _seed(s, tenant_slug="acme-8", specs=[
            {"name": "a", "indicators": [{"kind": "domain", "value": "shared"}], "findings": []},
            {"name": "b", "indicators": [{"kind": "domain", "value": "shared"}], "findings": []},
        ])
        tenant_id, sid_a, sid_b = tenant.id, a.id, b.id

    client = TestClient(app)
    r = client.get(
        f"/api/v4/specimens/{sid_a}/diff/{sid_b}",
        params={"tenant_id": tenant_id},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["specimen_a"]["id"] == sid_a
    assert body["specimen_b"]["id"] == sid_b
    assert "shared" in body["feature_diff"]["indicator_values"]
    assert "shared" in body["feature_diff"]["indicator_values"]["shared"]


def test_variant_diff_route_400_on_self(app_and_session):
    app, SessionLocal = app_and_session
    with SessionLocal() as s:
        tenant, [a] = _seed(s, tenant_slug="acme-9", specs=[
            {"name": "a", "indicators": [], "findings": []}
        ])
        tenant_id, sid_a = tenant.id, a.id
    client = TestClient(app)
    r = client.get(
        f"/api/v4/specimens/{sid_a}/diff/{sid_a}",
        params={"tenant_id": tenant_id},
    )
    assert r.status_code == 400
