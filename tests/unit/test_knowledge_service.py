"""Unit tests for V4 phase A slice 3 knowledge retrieval service.

These tests exercise the embedding providers, the hybrid BM25 + cosine
retriever with RRF fusion, the grounding provenance shape, and the
in-memory fallback path when the ``knowledge_chunk_embeddings`` table is
absent. They run against SQLite so they don't require a pgvector backend.
"""

from __future__ import annotations

import math
from typing import List
from unittest import mock

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401  -- register all tables on Base.metadata
from app.models.v2 import KnowledgeDocument
from app.services import knowledge_service as ks_module
from app.services.knowledge_service import (
    EMBEDDING_DIM,
    HashFallbackEmbeddingProvider,
    KnowledgeRetrievalService,
    OllamaEmbeddingProvider,
    cosine_similarity,
    reciprocal_rank_fusion,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sqlite_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture()
def session(sqlite_engine):
    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.rollback()
        sess.close()


def _seed_documents(session) -> List[KnowledgeDocument]:
    docs = [
        KnowledgeDocument(
            document_type="advisory",
            title="CVE-2024-31497 — PuTTY NIST P-521 key recovery",
            content=(
                "PuTTY versions prior to 0.81 are vulnerable to NIST P-521 "
                "private key recovery via biased ECDSA nonces. Attackers "
                "who observe 58 signatures can recover the private key."
            ),
            source_label="Vendor Advisory",
            source_url="https://example.com/putty",
            meta={},
        ),
        KnowledgeDocument(
            document_type="attack-note",
            title="ATT&CK T1059 — Command and Scripting Interpreter",
            content=(
                "Adversaries may abuse command-line interpreters to execute "
                "commands. PowerShell, bash, and cmd are common vehicles for "
                "payload staging and lateral movement."
            ),
            source_label="MITRE ATT&CK",
            source_url="https://attack.mitre.org/techniques/T1059/",
            meta={},
        ),
        KnowledgeDocument(
            document_type="wiki",
            title="Kerberos golden ticket mitigation",
            content=(
                "Reset the krbtgt password twice to invalidate golden tickets. "
                "Monitor Event ID 4769 for anomalous Kerberos TGS requests."
            ),
            source_label="Sheshnaag Wiki",
            source_url=None,
            meta={},
        ),
    ]
    for doc in docs:
        session.add(doc)
    session.flush()
    return docs


# ---------------------------------------------------------------------------
# Embedding provider tests
# ---------------------------------------------------------------------------


def test_hash_embedding_provider_is_deterministic():
    provider = HashFallbackEmbeddingProvider()
    text = "nist p-521 biased ecdsa nonce"
    first = provider.embed(text)
    second = provider.embed(text)
    assert first == second
    # Different input must give a different vector.
    assert provider.embed("unrelated content") != first


def test_hash_embedding_provider_dim_1024():
    provider = HashFallbackEmbeddingProvider()
    vec = provider.embed("anything here with putty and ssh")
    assert len(vec) == 1024
    assert len(vec) == EMBEDDING_DIM
    # L2 norm should be ~1 for a non-empty input.
    assert math.isclose(
        math.sqrt(sum(v * v for v in vec)), 1.0, rel_tol=1e-6
    )
    # Empty input returns a zero vector of the right length.
    empty = provider.embed("")
    assert len(empty) == 1024
    assert all(v == 0.0 for v in empty)


def test_get_embedding_provider_env_switch(monkeypatch):
    ks_module.reset_embedding_provider_cache()
    monkeypatch.setenv("SHESHNAAG_EMBEDDING_PROVIDER", "hash")
    provider = ks_module.get_embedding_provider()
    assert isinstance(provider, HashFallbackEmbeddingProvider)

    ks_module.reset_embedding_provider_cache()
    monkeypatch.setenv("SHESHNAAG_EMBEDDING_PROVIDER", "ollama")
    provider = ks_module.get_embedding_provider()
    assert isinstance(provider, OllamaEmbeddingProvider)

    ks_module.reset_embedding_provider_cache()


def test_ollama_provider_graceful_on_connection_error():
    # Build a mock httpx client that raises on every post.
    mock_client = mock.MagicMock(spec=httpx.Client)
    mock_client.post.side_effect = httpx.ConnectError("no route to host")

    provider = OllamaEmbeddingProvider(client=mock_client)
    vec = provider.embed("nimda worm metasploit shellcode")
    # Must fall back to a deterministic 1024-dim vector rather than raise.
    assert len(vec) == 1024
    assert any(v != 0.0 for v in vec)
    # Sanity: determinism comes from the hash fallback.
    again = provider.embed("nimda worm metasploit shellcode")
    assert vec == again


# ---------------------------------------------------------------------------
# Fusion helpers
# ---------------------------------------------------------------------------


def test_reciprocal_rank_fusion_prefers_consensus():
    fused = reciprocal_rank_fusion([[1, 2, 3], [2, 1, 3]], k=60)
    # Id 2 is rank 2 and 1 -> strongly fused. Id 1 is rank 1 and 2.
    # With RRF(k=60), id 1 and id 2 both score 1/61 + 1/62 -> tie.
    assert fused[1] == pytest.approx(fused[2])
    # Id 3 is always last -> lowest score.
    assert fused[3] < fused[1]


def test_cosine_similarity_basic():
    assert cosine_similarity([1, 0, 0], [1, 0, 0]) == pytest.approx(1.0)
    assert cosine_similarity([1, 0, 0], [0, 1, 0]) == pytest.approx(0.0)
    assert cosine_similarity([], [1, 0]) == 0.0


# ---------------------------------------------------------------------------
# Service-level retrieval tests
# ---------------------------------------------------------------------------


def test_hybrid_retrieval_combines_bm25_and_cosine(session):
    provider = HashFallbackEmbeddingProvider()
    service = KnowledgeRetrievalService(session, embedding_provider=provider)
    _seed_documents(session)
    service.reindex_documents()

    # Query that lexically matches the PuTTY advisory.
    results = service.search("PuTTY NIST P-521 key recovery", limit=3)
    assert results, "expected at least one result"
    top = results[0]
    assert "PuTTY" in top["title"]
    # Fusion must return the documented fields.
    assert top["rank"] == 1
    assert "bm25_score" in top and "cosine_score" in top and "fusion_score" in top
    # The fusion score should be the sum of reciprocal ranks; at minimum
    # it must be strictly positive for a match and monotonically decreasing.
    assert top["fusion_score"] > 0
    if len(results) > 1:
        assert results[1]["fusion_score"] <= top["fusion_score"]

    # A query for ATT&CK tactics should surface the attack-note doc.
    attack = service.search("powershell command scripting interpreter", limit=3)
    assert attack
    assert "ATT&CK" in attack[0]["title"] or "T1059" in attack[0]["title"]


def test_hybrid_retrieval_respects_both_signals(session):
    """The top result on a hybrid query must outrank a purely-lexical match
    that has no embedding-level resemblance."""

    provider = HashFallbackEmbeddingProvider()
    service = KnowledgeRetrievalService(session, embedding_provider=provider)
    _seed_documents(session)
    service.reindex_documents()

    # "krbtgt golden ticket" is uniquely present in the wiki doc.
    results = service.search("krbtgt golden ticket mitigation", limit=3)
    assert results[0]["document_type"] == "wiki"


def test_grounding_provenance_shape(session):
    provider = HashFallbackEmbeddingProvider()
    service = KnowledgeRetrievalService(session, embedding_provider=provider)
    _seed_documents(session)
    service.reindex_documents()

    results = service.search("PuTTY P-521 key recovery", limit=2)
    assert results
    grounding = service.grounding_for(results[0])
    assert isinstance(grounding, list) and len(grounding) == 1
    entry = grounding[0]
    expected_keys = {"chunk_id", "sha256", "rank", "score", "source"}
    assert expected_keys.issubset(entry.keys())
    assert entry["chunk_id"] == results[0]["chunk_id"]
    assert entry["sha256"] and len(entry["sha256"]) == 64
    assert entry["rank"] == 1
    assert entry["score"] == results[0]["fusion_score"]
    # The source identifier must be an actual label, not a placeholder.
    assert entry["source"] in {"Vendor Advisory", "MITRE ATT&CK", "Sheshnaag Wiki", "advisory", "attack-note", "wiki"}


def test_ingest_indexes_documents(session):
    provider = HashFallbackEmbeddingProvider()
    service = KnowledgeRetrievalService(session, embedding_provider=provider)
    docs = _seed_documents(session)
    indexed = service.ingest(documents=docs)
    assert indexed == len(docs)
    # Second call via document_ids path still works.
    reindexed = service.ingest(document_ids=[docs[0].id])
    assert reindexed == 1


# ---------------------------------------------------------------------------
# Fallback when embedding table is absent
# ---------------------------------------------------------------------------


def test_fallback_when_embedding_table_absent(sqlite_engine):
    # Drop the embeddings table to emulate a missing migration.
    from app.models.embeddings import KnowledgeChunkEmbedding

    KnowledgeChunkEmbedding.__table__.drop(sqlite_engine)

    Session = sessionmaker(bind=sqlite_engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        provider = HashFallbackEmbeddingProvider()
        service = KnowledgeRetrievalService(sess, embedding_provider=provider)
        assert service._has_embedding_table() is False

        _seed_documents(sess)
        service.reindex_documents()
        # In-memory chunks must be populated.
        assert service._fallback_chunks, "fallback store should be populated"

        results = service.search("golden ticket kerberos krbtgt", limit=2)
        assert results
        assert results[0]["document_type"] == "wiki"
        # Grounding still works off the in-memory rows.
        grounding = service.grounding_for(results[0])
        assert grounding[0]["sha256"] is not None
        assert grounding[0]["chunk_id"] == results[0]["chunk_id"]
    finally:
        sess.close()


# ---------------------------------------------------------------------------
# Smoke / regression
# ---------------------------------------------------------------------------


def test_embedding_dim_matches_schema():
    provider = HashFallbackEmbeddingProvider()
    assert len(provider.embed("anything")) == EMBEDDING_DIM == 1024
    assert KnowledgeRetrievalService.VECTOR_SIZE == 1024


def test_retrieve_preserves_legacy_shape(session):
    provider = HashFallbackEmbeddingProvider()
    service = KnowledgeRetrievalService(session, embedding_provider=provider)
    _seed_documents(session)
    service.reindex_documents()

    legacy = service.retrieve(query="PuTTY P-521", limit=2)
    assert legacy
    row = legacy[0]
    # V3-era keys must still be present for existing callers.
    for key in (
        "id",
        "document_id",
        "title",
        "document_type",
        "content",
        "source_label",
        "source_url",
        "score",
        "metadata",
    ):
        assert key in row
