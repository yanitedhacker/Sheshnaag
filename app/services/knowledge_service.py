"""Knowledge indexing and grounded retrieval over advisories and evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.models.sheshnaag import KnowledgeWikiPage, RawKnowledgeSource
from app.models.v2 import KnowledgeChunk, KnowledgeDocument, Tenant


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,}")


class KnowledgeRetrievalService:
    """Index documents into chunks and retrieve them with deterministic scoring."""

    VECTOR_SIZE = 24

    def __init__(self, session: Session):
        self.session = session

    def reindex_documents(self, *, document_ids: Optional[Sequence[int]] = None) -> int:
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
        """Replace a document's retrieval chunks."""
        self.session.query(KnowledgeChunk).filter(KnowledgeChunk.document_id == document.id).delete(synchronize_session=False)

        for chunk_index, chunk_text in enumerate(self._chunk_text(document.content)):
            normalized = self._normalize_text(f"{document.title}\n{chunk_text}")
            self.session.add(
                KnowledgeChunk(
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
                    embedding_model=settings.default_embedding_model,
                    embedding_vector=self._embed(normalized),
                    meta=document.meta or {},
                )
            )

    def retrieve(
        self,
        *,
        query: str,
        tenant: Optional[Tenant] = None,
        cve_db_ids: Optional[Sequence[int]] = None,
        limit: int = 6,
    ) -> List[dict]:
        """Retrieve the most relevant indexed chunks for a grounded prompt."""
        self.backfill_knowledge_layers()
        normalized_query = self._normalize_text(query)
        if not normalized_query:
            return []

        query_tokens = Counter(self._tokenize(normalized_query))
        query_vector = self._embed(normalized_query)

        chunk_query = self.session.query(KnowledgeChunk)
        if tenant is not None:
            chunk_query = chunk_query.filter(or_(KnowledgeChunk.tenant_id.is_(None), KnowledgeChunk.tenant_id == tenant.id))
        if cve_db_ids:
            chunk_query = chunk_query.filter(or_(KnowledgeChunk.cve_id.is_(None), KnowledgeChunk.cve_id.in_(cve_db_ids)))

        ranked: List[dict] = []
        for chunk in chunk_query.all():
            score = self._score_chunk(query_tokens, query_vector, chunk)
            if score <= 0:
                continue
            ranked.append(
                {
                    "id": chunk.id,
                    "document_id": chunk.document_id,
                    "title": chunk.title,
                    "document_type": chunk.document_type,
                    "content": chunk.content,
                    "source_label": chunk.source_label or chunk.document_type,
                    "source_url": chunk.source_url,
                    "score": round(score, 4),
                    "metadata": chunk.meta or {},
                }
            )

        ranked.sort(key=lambda item: item["score"], reverse=True)
        return ranked[:limit]

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
        digest_input = raw_body if raw_body else json.dumps(raw_payload, sort_keys=True, default=str)
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
                KnowledgeWikiPage.tenant_id == (tenant.id if tenant else None),
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
                tenant = self.session.query(Tenant).filter(Tenant.id == document.tenant_id).first()
            if document.document_type in {"advisory", "sbom-note"}:
                raw = self.create_raw_source(
                    source_kind=document.document_type,
                    source_key=source_url or f"{document.document_type}:{document.title}",
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

    def _upsert_retrieval_document_for_raw_source(self, source: RawKnowledgeSource) -> KnowledgeDocument:
        title = source.source_label or source.source_kind
        content = source.raw_body or json.dumps(source.raw_payload or {}, indent=2, sort_keys=True, default=str)
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

    def _upsert_retrieval_document_for_wiki_page(self, page: KnowledgeWikiPage) -> KnowledgeDocument:
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
            "meta": {"wiki_page_id": page.id, "source_ref_ids": page.source_ref_ids or [], **(page.meta or {})},
        }
        if record is None:
            record = KnowledgeDocument(**payload)
            self.session.add(record)
            self.session.flush()
        else:
            for key, value in payload.items():
                setattr(record, key, value)
        return record

    @staticmethod
    def _normalize_text(value: str) -> str:
        return " ".join(value.lower().split())

    def _chunk_text(self, content: str) -> List[str]:
        content = content.strip()
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
        counts = [0.0 for _ in range(self.VECTOR_SIZE)]
        tokens = self._tokenize(text)
        if not tokens:
            return counts
        for token in tokens:
            bucket = sum(ord(ch) for ch in token) % self.VECTOR_SIZE
            counts[bucket] += 1.0
        magnitude = math.sqrt(sum(value * value for value in counts)) or 1.0
        return [round(value / magnitude, 6) for value in counts]

    def _score_chunk(self, query_tokens: Counter, query_vector: List[float], chunk: KnowledgeChunk) -> float:
        chunk_tokens = Counter(self._tokenize(chunk.search_text or ""))
        lexical_overlap = sum(min(query_tokens[token], chunk_tokens[token]) for token in query_tokens)
        if lexical_overlap == 0:
            return 0.0

        chunk_vector = chunk.embedding_vector or [0.0 for _ in range(self.VECTOR_SIZE)]
        cosine = sum(left * right for left, right in zip(query_vector, chunk_vector))
        type_boost = 0.12 if chunk.document_type in {"advisory", "attack-note", "recommendation-note"} else 0.05
        return lexical_overlap + cosine + type_boost

    @staticmethod
    def _tokenize(value: str) -> List[str]:
        return TOKEN_RE.findall(value.lower())
