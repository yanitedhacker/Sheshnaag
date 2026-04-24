"""pgvector-backed embedding tables for knowledge RAG and specimen-behavior similarity.

These tables are new in V4 (phase A slice 3). They store the 1024-dimensional
embeddings produced by :mod:`app.services.knowledge_service` and the specimen
behavior embedder. The vector column type is dialect-aware: on PostgreSQL
(where the `pgvector` extension is installed) it resolves to
``pgvector.sqlalchemy.Vector(1024)``. On SQLite (dev / tests) and any other
dialect it falls back to JSON so the same ORM models remain usable without a
pgvector backend.

The migration in ``v4a02_pgvector_embeddings.py`` creates the concrete tables
(plus an IVFFLAT index on Postgres, skipped on SQLite).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.types import TypeDecorator, TypeEngine

from app.core.database import Base
from app.core.time import utc_now


VECTOR_DIM = 1024


class VectorOrJSON(TypeDecorator):
    """Dialect-aware vector column.

    Resolves to :class:`pgvector.sqlalchemy.Vector` on PostgreSQL and to a
    plain :class:`sqlalchemy.JSON` on every other dialect. This keeps the
    same ORM model usable against SQLite for local dev and unit tests while
    still taking advantage of pgvector / IVFFLAT / HNSW in production.
    """

    impl = JSON
    cache_ok = True

    def __init__(self, dim: int = VECTOR_DIM, *args: Any, **kwargs: Any) -> None:
        self.dim = dim
        super().__init__(*args, **kwargs)

    def load_dialect_impl(self, dialect) -> TypeEngine:  # type: ignore[override]
        if dialect.name == "postgresql":
            try:
                from pgvector.sqlalchemy import Vector  # type: ignore

                return dialect.type_descriptor(Vector(self.dim))
            except Exception:  # pragma: no cover - pgvector missing on postgres is exceptional
                return dialect.type_descriptor(JSON())
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value, dialect):  # type: ignore[override]
        if value is None:
            return None
        # On JSON fallback, store as a plain list. On pgvector, the library
        # accepts list / numpy / Vector and handles serialisation itself.
        if dialect.name == "postgresql":
            return value
        return list(value)

    def process_result_value(self, value, dialect):  # type: ignore[override]
        if value is None:
            return None
        return list(value)


def vector_column(dim: int = VECTOR_DIM) -> Column:
    """Factory for a dialect-aware vector column of the given dimensionality."""

    return Column(VectorOrJSON(dim), nullable=True)


class KnowledgeChunkEmbedding(Base):
    """1024-dim embedding for a knowledge chunk.

    The V4 design keeps the existing ``KnowledgeChunk`` row (see
    ``app.models.v2.KnowledgeChunk``) as the canonical chunk record; this
    table stores the pgvector-friendly embedding alongside provenance metadata
    (sha256, source_label) that the AI sidebar surfaces as clickable sources.
    """

    __tablename__ = "knowledge_chunk_embeddings"
    __table_args__ = (
        UniqueConstraint(
            "document_id", "chunk_index", name="uq_knowledge_chunk_embedding_doc_idx"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    chunk_id = Column(
        Integer,
        ForeignKey("knowledge_chunks.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    document_id = Column(Integer, index=True, nullable=True)
    tenant_id = Column(Integer, index=True, nullable=True)
    chunk_index = Column(Integer, nullable=False, default=0)
    sha256 = Column(
        String(128), nullable=False, index=True
    )  # ix_knowledge_chunk_embeddings_sha256
    source_label = Column(String(200), nullable=True)
    source_url = Column(Text, nullable=True)
    content_preview = Column(Text, nullable=True)
    embedding_model = Column(String(120), nullable=True)
    embedding = vector_column(VECTOR_DIM)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class SpecimenBehaviorEmbedding(Base):
    """1024-dim behaviour embedding per specimen (Pillar 7 Track B)."""

    __tablename__ = "specimen_behavior_embeddings"

    id = Column(Integer, primary_key=True, index=True)
    specimen_id = Column(
        Integer,
        ForeignKey("malware_specimens.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    feature_digest = Column(
        String(128), nullable=False, index=True
    )  # ix_specimen_behavior_embeddings_feature_digest
    embedding_model = Column(String(120), nullable=True)
    embedding = vector_column(VECTOR_DIM)
    created_at = Column(DateTime, default=utc_now, nullable=False)


__all__ = [
    "VECTOR_DIM",
    "VectorOrJSON",
    "vector_column",
    "KnowledgeChunkEmbedding",
    "SpecimenBehaviorEmbedding",
]
