"""Knowledge indexing and grounded retrieval over advisories and evidence."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.v2 import KnowledgeChunk, KnowledgeDocument, Tenant


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]{1,}")


class KnowledgeRetrievalService:
    """Index documents into chunks and retrieve them with deterministic scoring."""

    VECTOR_SIZE = 24

    def __init__(self, session: Session):
        self.session = session

    def reindex_documents(self, *, document_ids: Optional[Sequence[int]] = None) -> int:
        """Chunk and index all or selected knowledge documents."""
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
