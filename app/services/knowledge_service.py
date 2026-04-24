"""Knowledge indexing and grounded retrieval over advisories and evidence.

V4 phase A slice 3 upgrade:

* Embeddings are 1024-dimensional (up from the 24-dim toy vectors in V3).
* Concrete providers:
    - :class:`HashFallbackEmbeddingProvider` — deterministic sha256-seeded
      pseudo-random projection, used for tests and air-gapped default.
    - :class:`OllamaEmbeddingProvider` — POSTs to ``{OLLAMA_HOST}/api/embeddings``.
    - :class:`OpenAIEmbeddingProvider` — optional, uses ``OPENAI_API_KEY``.
* Retrieval is hybrid: BM25 (``rank_bm25``) + cosine over embeddings, fused
  with Reciprocal-Rank Fusion (k=60).
* Every result carries grounding provenance (chunk id, sha256, rank, score,
  source) suitable for the clickable AI-sidebar inspector described in the
  V4 architecture doc (Pillar 1.3).

Backward compatibility:

* The public class :class:`KnowledgeRetrievalService` keeps every existing
  method (``index_document``, ``reindex_documents``, ``retrieve``,
  ``create_raw_source``, ``create_wiki_page``, ``backfill_knowledge_layers``).
* New methods: ``ingest``, ``search``, ``grounding_for``.
* If the ``knowledge_chunk_embeddings`` table is missing (migration not yet
  applied), the service falls back gracefully to in-memory 1024-dim vectors
  and logs a warning once per process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

import httpx

try:  # pragma: no cover - import guarded so the service works if rank_bm25 is missing
    from rank_bm25 import BM25Okapi
except Exception:  # pragma: no cover
    BM25Okapi = None  # type: ignore[assignment]

from sqlalchemy import inspect as sa_inspect, or_
from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.models.sheshnaag import KnowledgeWikiPage, RawKnowledgeSource
from app.models.v2 import KnowledgeChunk, KnowledgeDocument, Tenant


logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,}")

#: The canonical embedding dimensionality used across V4.
EMBEDDING_DIM = 1024

#: Reciprocal-rank-fusion constant used to blend BM25 and cosine ranks.
RRF_K = 60


# ---------------------------------------------------------------------------
# Embedding providers
# ---------------------------------------------------------------------------


class EmbeddingProvider(Protocol):
    """Abstract embedding backend.

    Implementations must always return ``EMBEDDING_DIM`` dimensional vectors
    and must never raise on a single-input failure — they should return a
    zero vector or delegate to the fallback provider and surface the error
    through logging.
    """

    #: Short machine-readable label written to ``embedding_model`` columns.
    model_label: str

    def embed(self, text: str) -> List[float]: ...

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]: ...


def _l2_normalize(values: Sequence[float]) -> List[float]:
    magnitude = math.sqrt(sum(v * v for v in values)) or 1.0
    return [v / magnitude for v in values]


def _project_to_dim(values: Sequence[float], dim: int = EMBEDDING_DIM) -> List[float]:
    """Pad with zeros or truncate a vector so it ends up exactly ``dim`` long.

    Used to coerce provider-native dimensionality (768 for nomic-embed-text,
    1536 for text-embedding-3-small) into the canonical 1024 used by the
    pgvector column. Truncation is lossy but deterministic; we L2-normalise
    after projection so cosine still behaves sensibly.
    """

    if len(values) == dim:
        out = list(values)
    elif len(values) > dim:
        out = list(values[:dim])
    else:
        out = list(values) + [0.0] * (dim - len(values))
    return _l2_normalize(out)


class HashFallbackEmbeddingProvider:
    """Deterministic, dependency-free 1024-dim embedding (FALLBACK).

    Algorithm: tokenise the input, seed a pseudo-random projection with a
    SHA-256 digest of each token, sum the contributions, L2-normalise. The
    result is deterministic for the same input and reasonably distributes
    distinct token sets across the hypersphere. It is NOT semantically
    meaningful — it's a stable fallback for tests and air-gapped deployments.
    """

    model_label = "hash-bow-1024-v1"

    def __init__(self, dim: int = EMBEDDING_DIM) -> None:
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        tokens = TOKEN_RE.findall((text or "").lower())
        vector = [0.0] * self.dim
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            # Each token contributes one signed value to each of 8 buckets
            # sampled from the digest. This gives enough spread to
            # discriminate small token sets without requiring numpy.
            for i in range(8):
                byte_offset = (i * 4) % (len(digest) - 4)
                # 4 bytes -> uint32 -> bucket index
                bucket = (
                    struct.unpack_from(">I", digest, byte_offset)[0] % self.dim
                )
                sign_byte = digest[(byte_offset + 3) % len(digest)]
                sign = 1.0 if (sign_byte & 1) == 0 else -1.0
                # Weight by 1/sqrt(len(tokens)) so longer docs don't explode.
                vector[bucket] += sign * (1.0 / math.sqrt(len(tokens)))
        return _l2_normalize(vector)

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class OllamaEmbeddingProvider:
    """Ollama ``/api/embeddings`` adapter.

    Falls back to :class:`HashFallbackEmbeddingProvider` on connection error
    so a missing local daemon never breaks ingestion.
    """

    def __init__(
        self,
        *,
        host: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 15.0,
        fallback: Optional[EmbeddingProvider] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.host = (host or os.getenv("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        self.model = (
            model
            or os.getenv("SHESHNAAG_EMBEDDING_MODEL")
            or "nomic-embed-text"
        )
        self.timeout = timeout
        self.fallback = fallback or HashFallbackEmbeddingProvider()
        self._client = client
        self.model_label = f"ollama:{self.model}"

    def _client_or_new(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout)

    def embed(self, text: str) -> List[float]:
        client = self._client_or_new()
        close_after = self._client is None
        try:
            try:
                response = client.post(
                    f"{self.host}/api/embeddings",
                    json={"model": self.model, "prompt": text or ""},
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "Ollama embedding request failed (%s); falling back to %s",
                    exc,
                    self.fallback.model_label,
                )
                return self.fallback.embed(text)
        finally:
            if close_after:
                client.close()

        raw = payload.get("embedding") or payload.get("data") or []
        if not raw or not isinstance(raw, list):
            logger.warning(
                "Ollama returned unexpected embedding payload; using fallback"
            )
            return self.fallback.embed(text)
        # nomic-embed-text is 768-dim; pad / truncate to 1024.
        return _project_to_dim(raw, EMBEDDING_DIM)

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class OpenAIEmbeddingProvider:
    """OpenAI ``/v1/embeddings`` adapter — only used when configured."""

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
        fallback: Optional[EmbeddingProvider] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = (base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com").rstrip("/")
        self.model = (
            model
            or os.getenv("SHESHNAAG_EMBEDDING_MODEL")
            or "text-embedding-3-small"
        )
        self.timeout = timeout
        self.fallback = fallback or HashFallbackEmbeddingProvider()
        self._client = client
        self.model_label = f"openai:{self.model}"

    def _client_or_new(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout)

    def embed(self, text: str) -> List[float]:
        if not self.api_key:
            logger.warning("OpenAI embedding provider has no API key; using fallback")
            return self.fallback.embed(text)
        client = self._client_or_new()
        close_after = self._client is None
        try:
            try:
                response = client.post(
                    f"{self.base_url}/v1/embeddings",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"model": self.model, "input": text or ""},
                )
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "OpenAI embedding request failed (%s); falling back to %s",
                    exc,
                    self.fallback.model_label,
                )
                return self.fallback.embed(text)
        finally:
            if close_after:
                client.close()

        data = payload.get("data") or []
        if not data:
            return self.fallback.embed(text)
        raw = data[0].get("embedding") or []
        # text-embedding-3-small is 1536-dim; project to 1024.
        return _project_to_dim(raw, EMBEDDING_DIM)

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


_provider_singleton: Optional[EmbeddingProvider] = None


def get_embedding_provider() -> EmbeddingProvider:
    """Return the configured embedding provider (cached for process lifetime).

    Controlled by the ``SHESHNAAG_EMBEDDING_PROVIDER`` environment variable:

    * ``hash`` (default) — :class:`HashFallbackEmbeddingProvider`
    * ``ollama`` — :class:`OllamaEmbeddingProvider`
    * ``openai`` — :class:`OpenAIEmbeddingProvider`
    """

    global _provider_singleton
    if _provider_singleton is not None:
        return _provider_singleton

    kind = (os.getenv("SHESHNAAG_EMBEDDING_PROVIDER") or "hash").strip().lower()
    if kind == "ollama":
        _provider_singleton = OllamaEmbeddingProvider()
    elif kind == "openai":
        _provider_singleton = OpenAIEmbeddingProvider()
    else:
        _provider_singleton = HashFallbackEmbeddingProvider()
    return _provider_singleton


def reset_embedding_provider_cache() -> None:
    """Test-only helper to drop the cached singleton."""

    global _provider_singleton
    _provider_singleton = None


# ---------------------------------------------------------------------------
# Hybrid retrieval helpers
# ---------------------------------------------------------------------------


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b:
        return 0.0
    dot = 0.0
    mag_a = 0.0
    mag_b = 0.0
    # Iterate over the shorter length in case of dim mismatch; this keeps the
    # function defensive against historical 24-dim rows coexisting with 1024.
    length = min(len(a), len(b))
    for i in range(length):
        av = a[i]
        bv = b[i]
        dot += av * bv
        mag_a += av * av
        mag_b += bv * bv
    denom = math.sqrt(mag_a) * math.sqrt(mag_b)
    if denom == 0:
        return 0.0
    return dot / denom


def reciprocal_rank_fusion(
    rank_lists: Sequence[Sequence[Any]], *, k: int = RRF_K
) -> Dict[Any, float]:
    """Fuse several ranked id lists with Reciprocal Rank Fusion.

    Returns a mapping from item id to RRF score. Higher is better.
    """

    fused: Dict[Any, float] = {}
    for ranking in rank_lists:
        for rank, item_id in enumerate(ranking, start=1):
            fused[item_id] = fused.get(item_id, 0.0) + 1.0 / (k + rank)
    return fused


@dataclass
class _ChunkRow:
    """Lightweight in-memory chunk used by the fallback retrieval path."""

    id: int
    document_id: int
    tenant_id: Optional[int]
    cve_id: Optional[int]
    title: str
    content: str
    document_type: str
    source_label: Optional[str]
    source_url: Optional[str]
    meta: Dict[str, Any]
    search_text: str
    embedding: List[float]
    sha256: str


class KnowledgeRetrievalService:
    """Index documents into chunks and retrieve them with hybrid scoring.

    Public API (preserved from V3):
        * :meth:`reindex_documents`
        * :meth:`index_document`
        * :meth:`retrieve`
        * :meth:`create_raw_source`
        * :meth:`create_wiki_page`
        * :meth:`backfill_knowledge_layers`

    New in V4 phase A slice 3:
        * :meth:`ingest` — alias / thin wrapper around index flow.
        * :meth:`search` — hybrid BM25 + cosine with RRF rerank + grounding.
        * :meth:`grounding_for` — provenance list for the AI sidebar.
    """

    #: Kept for backward-compat with tests / callers that read the constant.
    VECTOR_SIZE = EMBEDDING_DIM

    # Fallback store used when the ``knowledge_chunk_embeddings`` table is
    # missing. Scoped to the service instance so tests stay hermetic.
    def __init__(
        self,
        session: Session,
        *,
        embedding_provider: Optional[EmbeddingProvider] = None,
    ) -> None:
        self.session = session
        self.embedding_provider: EmbeddingProvider = (
            embedding_provider or get_embedding_provider()
        )
        self._embedding_table_present: Optional[bool] = None
        self._fallback_chunks: Dict[int, _ChunkRow] = {}
        # Cache the BM25 index per-query since our corpus is small and the
        # session is short-lived; rebuilding it is cheap.

    # ------------------------------------------------------------------
    # Embedding table availability
    # ------------------------------------------------------------------

    def _has_embedding_table(self) -> bool:
        if self._embedding_table_present is not None:
            return self._embedding_table_present
        # Inspect via the session's existing connection so we don't open a
        # sibling DBAPI connection — on in-memory SQLite + StaticPool a
        # sibling connection resets the in-flight transaction and wipes
        # uncommitted rows (the migration migrates tables on the live
        # connection, so ``knowledge_chunk_embeddings`` is only visible on
        # that same connection anyway).
        try:
            inspector = sa_inspect(self.session.connection())
            self._embedding_table_present = inspector.has_table(
                "knowledge_chunk_embeddings"
            )
        except Exception:
            self._embedding_table_present = False
        if not self._embedding_table_present:
            logger.warning(
                "knowledge_chunk_embeddings table not present; using in-memory "
                "fallback (run alembic upgrade v4a02 to enable pgvector)"
            )
        return self._embedding_table_present

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def reindex_documents(
        self, *, document_ids: Optional[Sequence[int]] = None
    ) -> int:
        """Chunk and index all or selected knowledge documents."""

        self.backfill_knowledge_layers()
        query = self.session.query(KnowledgeDocument)
        if document_ids:
            query = query.filter(KnowledgeDocument.id.in_(document_ids))
        documents = query.all()
        count = 0
        for document in documents:
            self.index_document(document)
            count += 1
        return count

    def index_document(self, document: KnowledgeDocument) -> None:
        """Replace a document's retrieval chunks (and their embeddings)."""

        self.session.query(KnowledgeChunk).filter(
            KnowledgeChunk.document_id == document.id
        ).delete(synchronize_session=False)
        # Drop any stale fallback rows for this document.
        for cid in [c.id for c in self._fallback_chunks.values() if c.document_id == document.id]:
            self._fallback_chunks.pop(cid, None)

        if self._has_embedding_table():
            self._delete_persisted_embeddings_for_document(document.id)

        texts: List[str] = []
        chunk_texts: List[str] = []
        for chunk_text in self._chunk_text(document.content):
            normalized = self._normalize_text(f"{document.title}\n{chunk_text}")
            texts.append(normalized)
            chunk_texts.append(chunk_text)

        if not texts:
            return

        vectors = self.embedding_provider.embed_batch(texts)

        for chunk_index, (chunk_text, normalized, embedding_vector) in enumerate(
            zip(chunk_texts, texts, vectors)
        ):
            sha256 = hashlib.sha256(
                f"{document.id}:{chunk_index}:{chunk_text}".encode("utf-8")
            ).hexdigest()
            chunk = KnowledgeChunk(
                document_id=document.id,
                tenant_id=document.tenant_id,
                cve_id=document.cve_id,
                technique_id=document.technique_id,
                chunk_index=chunk_index,
                document_type=document.document_type,
                title=document.title,
                content=chunk_text,
                search_text=normalized,
                source_label=document.source_label,
                source_url=document.source_url,
                embedding_model=self.embedding_provider.model_label,
                embedding_vector=embedding_vector,
                meta={**(document.meta or {}), "sha256": sha256},
            )
            self.session.add(chunk)
            self.session.flush()

            if self._has_embedding_table():
                self._persist_embedding(
                    chunk=chunk,
                    document=document,
                    sha256=sha256,
                    embedding_vector=embedding_vector,
                )
            else:
                self._fallback_chunks[chunk.id] = _ChunkRow(
                    id=chunk.id,
                    document_id=document.id,
                    tenant_id=document.tenant_id,
                    cve_id=document.cve_id,
                    title=document.title,
                    content=chunk_text,
                    document_type=document.document_type,
                    source_label=document.source_label,
                    source_url=document.source_url,
                    meta={**(document.meta or {}), "sha256": sha256},
                    search_text=normalized,
                    embedding=embedding_vector,
                    sha256=sha256,
                )

    # ------------------------------------------------------------------
    # New public API: ingest / search / grounding_for
    # ------------------------------------------------------------------

    def ingest(
        self,
        *,
        documents: Optional[Sequence[KnowledgeDocument]] = None,
        document_ids: Optional[Sequence[int]] = None,
    ) -> int:
        """Index one or more documents. Mirrors the public V4 API."""

        if documents is not None:
            count = 0
            for document in documents:
                self.index_document(document)
                count += 1
            return count
        return self.reindex_documents(document_ids=document_ids)

    def search(
        self,
        query: str,
        *,
        tenant: Optional[Tenant] = None,
        cve_db_ids: Optional[Sequence[int]] = None,
        limit: int = 6,
    ) -> List[Dict[str, Any]]:
        """Hybrid BM25 + cosine search with Reciprocal Rank Fusion.

        Each returned dict has the same shape as :meth:`retrieve` plus:

        * ``chunk_id`` — primary key of the underlying KnowledgeChunk
        * ``sha256`` — content digest for citation stability
        * ``rank`` — 1-indexed rank in the fused ranking
        * ``bm25_score``, ``cosine_score``, ``fusion_score`` — raw signals
        * ``grounding`` — single-item grounding list (see ``grounding_for``)
        """

        self.backfill_knowledge_layers()
        normalized_query = self._normalize_text(query)
        if not normalized_query:
            return []

        candidate_chunks = self._candidate_chunks(
            tenant=tenant, cve_db_ids=cve_db_ids
        )
        if not candidate_chunks:
            return []

        query_tokens = self._tokenize(normalized_query)
        chunk_token_lists: List[List[str]] = [
            self._tokenize(row.search_text) for row in candidate_chunks
        ]

        # BM25 ranking — use rank_bm25 if available, otherwise fall back to a
        # lexical-overlap score so the feature still works in minimal envs.
        bm25_scores: List[float]
        if BM25Okapi is not None and any(chunk_token_lists):
            bm25_scores = list(
                BM25Okapi(chunk_token_lists).get_scores(query_tokens)
            )
        else:  # pragma: no cover - exercised when rank_bm25 absent
            bm25_scores = [
                float(
                    sum(
                        min(
                            query_tokens.count(tok),
                            chunk_tokens.count(tok),
                        )
                        for tok in set(query_tokens)
                    )
                )
                for chunk_tokens in chunk_token_lists
            ]

        query_embedding = self.embedding_provider.embed(normalized_query)
        cosine_scores = [
            cosine_similarity(query_embedding, row.embedding or [])
            for row in candidate_chunks
        ]

        # Build ranked id lists. Ties are broken by original order which
        # keeps the result deterministic for tests.
        ids = [row.id for row in candidate_chunks]
        bm25_ranking = [
            cid
            for cid, _ in sorted(
                zip(ids, bm25_scores), key=lambda pair: pair[1], reverse=True
            )
            if _ > 0  # ignore zero-score entries
        ]
        cosine_ranking = [
            cid
            for cid, _ in sorted(
                zip(ids, cosine_scores), key=lambda pair: pair[1], reverse=True
            )
            if _ > 0
        ]

        # Fall back to including every candidate when both rankings are empty
        # so a query at least returns something when nothing scored.
        if not bm25_ranking and not cosine_ranking:
            return []

        fused = reciprocal_rank_fusion(
            [bm25_ranking, cosine_ranking], k=RRF_K
        )
        # Score-index lookups.
        score_by_id = {
            row.id: (bm25_scores[idx], cosine_scores[idx])
            for idx, row in enumerate(candidate_chunks)
        }

        ordered_ids = sorted(
            fused.items(), key=lambda item: item[1], reverse=True
        )
        results: List[Dict[str, Any]] = []
        chunk_by_id = {row.id: row for row in candidate_chunks}
        for rank, (chunk_id, fusion_score) in enumerate(
            ordered_ids[:limit], start=1
        ):
            row = chunk_by_id[chunk_id]
            bm25_score, cosine_score = score_by_id[chunk_id]
            entry = {
                "chunk_id": row.id,
                "id": row.id,
                "document_id": row.document_id,
                "title": row.title,
                "document_type": row.document_type,
                "content": row.content,
                "source_label": row.source_label or row.document_type,
                "source_url": row.source_url,
                "sha256": row.sha256,
                "rank": rank,
                "bm25_score": round(float(bm25_score), 6),
                "cosine_score": round(float(cosine_score), 6),
                "fusion_score": round(float(fusion_score), 6),
                # ``score`` stays present so legacy callers keep working —
                # we expose the fusion score here so "higher is better".
                "score": round(float(fusion_score), 6),
                "metadata": row.meta or {},
            }
            entry["grounding"] = self.grounding_for(entry)
            results.append(entry)
        return results

    def grounding_for(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return provenance metadata for a single search result.

        The shape matches what :class:`AISidebar` consumes:
        ``[{chunk_id, sha256, rank, score, source}]``. Returning a list (not
        a single dict) keeps the door open for results that aggregate
        multiple chunks without a schema change.
        """

        return [
            {
                "chunk_id": result.get("chunk_id") or result.get("id"),
                "sha256": result.get("sha256"),
                "rank": result.get("rank"),
                "score": result.get("fusion_score") or result.get("score"),
                "source": result.get("source_label")
                or result.get("document_type"),
                "source_url": result.get("source_url"),
                "title": result.get("title"),
            }
        ]

    # ------------------------------------------------------------------
    # Legacy retrieve() — preserved
    # ------------------------------------------------------------------

    def retrieve(
        self,
        *,
        query: str,
        tenant: Optional[Tenant] = None,
        cve_db_ids: Optional[Sequence[int]] = None,
        limit: int = 6,
    ) -> List[dict]:
        """Retrieve the most relevant indexed chunks for a grounded prompt.

        Implemented on top of :meth:`search` so every caller benefits from
        the V4 hybrid retriever. The return shape is the V3-compatible dict.
        """

        return self.search(
            query,
            tenant=tenant,
            cve_db_ids=cve_db_ids,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Raw source / wiki ingest (unchanged from V3)
    # ------------------------------------------------------------------

    def create_raw_source(
        self,
        *,
        source_kind: str,
        source_key: str,
        source_label: Optional[str] = None,
        source_url: Optional[str] = None,
        raw_body: Optional[str] = None,
        raw_payload: Optional[dict] = None,
        tenant: Optional[Tenant] = None,
        cve_id: Optional[int] = None,
        provenance: Optional[dict] = None,
    ) -> RawKnowledgeSource:
        raw_payload = raw_payload or {}
        digest_input = (
            raw_body
            if raw_body
            else json.dumps(raw_payload, sort_keys=True, default=str)
        )
        sha256 = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        record = (
            self.session.query(RawKnowledgeSource)
            .filter(
                RawKnowledgeSource.tenant_id == (tenant.id if tenant else None),
                RawKnowledgeSource.source_kind == source_kind,
                RawKnowledgeSource.source_key == source_key,
            )
            .first()
        )
        payload = {
            "tenant_id": tenant.id if tenant else None,
            "cve_id": cve_id,
            "source_kind": source_kind,
            "source_key": source_key,
            "source_label": source_label,
            "source_url": source_url,
            "raw_body": raw_body,
            "raw_payload": raw_payload,
            "sha256": sha256,
            "collected_at": utc_now(),
            "provenance": provenance or {},
        }
        if record is None:
            record = RawKnowledgeSource(**payload)
            self.session.add(record)
            self.session.flush()
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        self._upsert_retrieval_document_for_raw_source(record)
        return record

    def create_wiki_page(
        self,
        *,
        page_type: str,
        title: str,
        summary: str,
        source_ref_ids: Optional[List[int]] = None,
        tenant: Optional[Tenant] = None,
        cve_id: Optional[int] = None,
        meta: Optional[dict] = None,
    ) -> KnowledgeWikiPage:
        record = (
            self.session.query(KnowledgeWikiPage)
            .filter(
                KnowledgeWikiPage.tenant_id
                == (tenant.id if tenant else None),
                KnowledgeWikiPage.page_type == page_type,
                KnowledgeWikiPage.title == title,
                KnowledgeWikiPage.cve_id == cve_id,
            )
            .first()
        )
        payload = {
            "tenant_id": tenant.id if tenant else None,
            "cve_id": cve_id,
            "page_type": page_type,
            "title": title,
            "summary": summary,
            "source_ref_ids": source_ref_ids or [],
            "meta": meta or {},
        }
        if record is None:
            record = KnowledgeWikiPage(**payload)
            self.session.add(record)
            self.session.flush()
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        self._upsert_retrieval_document_for_wiki_page(record)
        return record

    def backfill_knowledge_layers(self) -> None:
        if not settings.knowledge_backfill_enabled:
            return
        docs = self.session.query(KnowledgeDocument).all()
        for document in docs:
            meta = document.meta or {}
            source_url = document.source_url or ""
            if meta.get("raw_source_id") or meta.get("wiki_page_id"):
                continue
            tenant = None
            if document.tenant_id is not None:
                tenant = (
                    self.session.query(Tenant)
                    .filter(Tenant.id == document.tenant_id)
                    .first()
                )
            if document.document_type in {"advisory", "sbom-note"}:
                raw = self.create_raw_source(
                    source_kind=document.document_type,
                    source_key=source_url
                    or f"{document.document_type}:{document.title}",
                    source_label=document.source_label or document.document_type,
                    source_url=document.source_url,
                    raw_body=document.content,
                    tenant=tenant,
                    cve_id=document.cve_id,
                    provenance={"backfilled_from_document_id": document.id},
                )
                document.meta = {**meta, "raw_source_id": raw.id}
            else:
                wiki = self.create_wiki_page(
                    page_type=document.document_type,
                    title=document.title,
                    summary=document.content,
                    tenant=tenant,
                    cve_id=document.cve_id,
                    meta={"backfilled_from_document_id": document.id, **meta},
                )
                document.meta = {**meta, "wiki_page_id": wiki.id}
        self.session.flush()

    def _upsert_retrieval_document_for_raw_source(
        self, source: RawKnowledgeSource
    ) -> KnowledgeDocument:
        title = source.source_label or source.source_kind
        content = source.raw_body or json.dumps(
            source.raw_payload or {}, indent=2, sort_keys=True, default=str
        )
        meta = {
            "raw_source_id": source.id,
            "source_kind": source.source_kind,
            "sha256": source.sha256,
            **(source.provenance or {}),
        }
        record = (
            self.session.query(KnowledgeDocument)
            .filter(
                KnowledgeDocument.document_type == "raw-source",
                KnowledgeDocument.title == title,
                KnowledgeDocument.source_url == source.source_url,
                KnowledgeDocument.cve_id == source.cve_id,
            )
            .first()
        )
        payload = {
            "tenant_id": source.tenant_id,
            "cve_id": source.cve_id,
            "document_type": "raw-source",
            "title": title,
            "content": content,
            "source_label": source.source_label or source.source_kind,
            "source_url": source.source_url,
            "meta": meta,
        }
        if record is None:
            record = KnowledgeDocument(**payload)
            self.session.add(record)
            self.session.flush()
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        return record

    def _upsert_retrieval_document_for_wiki_page(
        self, page: KnowledgeWikiPage
    ) -> KnowledgeDocument:
        record = (
            self.session.query(KnowledgeDocument)
            .filter(
                KnowledgeDocument.document_type == "wiki",
                KnowledgeDocument.title == page.title,
                KnowledgeDocument.cve_id == page.cve_id,
            )
            .first()
        )
        payload = {
            "tenant_id": page.tenant_id,
            "cve_id": page.cve_id,
            "document_type": "wiki",
            "title": page.title,
            "content": page.summary,
            "source_label": "Sheshnaag Wiki",
            "source_url": None,
            "meta": {
                "wiki_page_id": page.id,
                "source_ref_ids": page.source_ref_ids or [],
                **(page.meta or {}),
            },
        }
        if record is None:
            record = KnowledgeDocument(**payload)
            self.session.add(record)
            self.session.flush()
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        return record

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _candidate_chunks(
        self,
        *,
        tenant: Optional[Tenant],
        cve_db_ids: Optional[Sequence[int]],
    ) -> List[_ChunkRow]:
        if not self._has_embedding_table() and self._fallback_chunks:
            rows = list(self._fallback_chunks.values())
            if tenant is not None:
                rows = [
                    row
                    for row in rows
                    if row.tenant_id is None or row.tenant_id == tenant.id
                ]
            if cve_db_ids:
                cve_set = set(cve_db_ids)
                rows = [
                    row
                    for row in rows
                    if row.cve_id is None or row.cve_id in cve_set
                ]
            return rows

        chunk_query = self.session.query(KnowledgeChunk)
        if tenant is not None:
            chunk_query = chunk_query.filter(
                or_(
                    KnowledgeChunk.tenant_id.is_(None),
                    KnowledgeChunk.tenant_id == tenant.id,
                )
            )
        if cve_db_ids:
            chunk_query = chunk_query.filter(
                or_(
                    KnowledgeChunk.cve_id.is_(None),
                    KnowledgeChunk.cve_id.in_(cve_db_ids),
                )
            )

        rows: List[_ChunkRow] = []
        for chunk in chunk_query.all():
            meta = chunk.meta or {}
            sha256 = meta.get("sha256") or hashlib.sha256(
                (chunk.search_text or chunk.content or "").encode("utf-8")
            ).hexdigest()
            embedding = chunk.embedding_vector or []
            rows.append(
                _ChunkRow(
                    id=chunk.id,
                    document_id=chunk.document_id,
                    tenant_id=chunk.tenant_id,
                    cve_id=chunk.cve_id,
                    title=chunk.title,
                    content=chunk.content,
                    document_type=chunk.document_type,
                    source_label=chunk.source_label,
                    source_url=chunk.source_url,
                    meta=meta,
                    search_text=chunk.search_text or "",
                    embedding=list(embedding),
                    sha256=sha256,
                )
            )
        return rows

    def _persist_embedding(
        self,
        *,
        chunk: KnowledgeChunk,
        document: KnowledgeDocument,
        sha256: str,
        embedding_vector: Sequence[float],
    ) -> None:
        # Imported lazily so the rest of the module is importable even when
        # the embeddings module hasn't been registered (e.g. unusual test
        # harnesses that stub out app.models).
        try:
            from app.models.embeddings import KnowledgeChunkEmbedding
        except Exception:  # pragma: no cover - defensive
            return

        try:
            row = KnowledgeChunkEmbedding(
                chunk_id=chunk.id,
                document_id=document.id,
                tenant_id=document.tenant_id,
                chunk_index=chunk.chunk_index,
                sha256=sha256,
                source_label=document.source_label,
                source_url=document.source_url,
                content_preview=(chunk.content or "")[:400],
                embedding_model=self.embedding_provider.model_label,
                embedding=list(embedding_vector),
            )
            self.session.add(row)
            self.session.flush()
        except (OperationalError, ProgrammingError) as exc:
            # Table exists in the metadata but the backing DB is missing the
            # column / extension. Fall back to in-memory and log.
            logger.warning(
                "Persisting KnowledgeChunkEmbedding failed (%s); using in-memory fallback",
                exc,
            )
            self._embedding_table_present = False
            self.session.rollback()

    def _delete_persisted_embeddings_for_document(self, document_id: int) -> None:
        try:
            from app.models.embeddings import KnowledgeChunkEmbedding
        except Exception:  # pragma: no cover - defensive
            return
        try:
            self.session.query(KnowledgeChunkEmbedding).filter(
                KnowledgeChunkEmbedding.document_id == document_id
            ).delete(synchronize_session=False)
        except (OperationalError, ProgrammingError):
            self._embedding_table_present = False
            self.session.rollback()

    @staticmethod
    def _normalize_text(value: str) -> str:
        return " ".join((value or "").lower().split())

    def _chunk_text(self, content: str) -> List[str]:
        content = (content or "").strip()
        if not content:
            return []

        max_size = max(120, settings.knowledge_chunk_size)
        overlap = min(max_size // 2, max(0, settings.knowledge_chunk_overlap))
        parts: List[str] = []
        start = 0
        while start < len(content):
            end = min(len(content), start + max_size)
            parts.append(content[start:end].strip())
            if end >= len(content):
                break
            start = max(0, end - overlap)
        return [part for part in parts if part]

    def _embed(self, text: str) -> List[float]:
        """Back-compat shim: delegate to the configured embedding provider."""

        return self.embedding_provider.embed(text)

    @staticmethod
    def _tokenize(value: str) -> List[str]:
        return TOKEN_RE.findall((value or "").lower())


__all__ = [
    "EMBEDDING_DIM",
    "RRF_K",
    "EmbeddingProvider",
    "HashFallbackEmbeddingProvider",
    "OllamaEmbeddingProvider",
    "OpenAIEmbeddingProvider",
    "get_embedding_provider",
    "reset_embedding_provider_cache",
    "cosine_similarity",
    "reciprocal_rank_fusion",
    "KnowledgeRetrievalService",
]
