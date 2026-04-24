"""V4 phase A slice 3 — pgvector-backed embedding tables.

Creates two tables that hold 1024-dim embeddings:

* ``knowledge_chunk_embeddings`` — hybrid BM25 + cosine RAG over
  :class:`app.models.v2.KnowledgeChunk` rows.
* ``specimen_behavior_embeddings`` — variant-diff / similarity search over
  detonation behaviour features (Pillar 7 Track B).

On PostgreSQL the ``vector`` extension is installed and an IVFFLAT index is
built on the embedding column. On SQLite (used for local dev / tests) the
extension step is skipped and the embedding column is stored as JSON; this
keeps the same schema usable for deterministic unit tests without pgvector.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# Alembic identifiers — chain after the capability-policy migration.
revision = "v4a02"
down_revision = "v4a01"
branch_labels = None
depends_on = None


VECTOR_DIM = 1024


def _vector_column(dialect_name: str) -> sa.types.TypeEngine:
    if dialect_name == "postgresql":
        try:
            from pgvector.sqlalchemy import Vector  # type: ignore

            return Vector(VECTOR_DIM)
        except Exception:  # pragma: no cover - pgvector missing on postgres is exceptional
            return sa.JSON()
    return sa.JSON()


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    vector_type = _vector_column(dialect)

    op.create_table(
        "knowledge_chunk_embeddings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "chunk_id",
            sa.Integer(),
            sa.ForeignKey("knowledge_chunks.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("document_id", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("chunk_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(length=128), nullable=False),
        sa.Column("source_label", sa.String(length=200), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("content_preview", sa.Text(), nullable=True),
        sa.Column("embedding_model", sa.String(length=120), nullable=True),
        sa.Column("embedding", vector_type, nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "document_id",
            "chunk_index",
            name="uq_knowledge_chunk_embedding_doc_idx",
        ),
    )
    op.create_index(
        "ix_knowledge_chunk_embeddings_chunk_id",
        "knowledge_chunk_embeddings",
        ["chunk_id"],
    )
    op.create_index(
        "ix_knowledge_chunk_embeddings_document_id",
        "knowledge_chunk_embeddings",
        ["document_id"],
    )
    op.create_index(
        "ix_knowledge_chunk_embeddings_tenant_id",
        "knowledge_chunk_embeddings",
        ["tenant_id"],
    )
    op.create_index(
        "ix_knowledge_chunk_embeddings_sha256",
        "knowledge_chunk_embeddings",
        ["sha256"],
    )

    op.create_table(
        "specimen_behavior_embeddings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "specimen_id",
            sa.Integer(),
            sa.ForeignKey("malware_specimens.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("feature_digest", sa.String(length=128), nullable=False),
        sa.Column("embedding_model", sa.String(length=120), nullable=True),
        sa.Column("embedding", vector_type, nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_specimen_behavior_embeddings_specimen_id",
        "specimen_behavior_embeddings",
        ["specimen_id"],
    )
    op.create_index(
        "ix_specimen_behavior_embeddings_digest",
        "specimen_behavior_embeddings",
        ["feature_digest"],
    )

    # Vector indexes are Postgres-only and require the `vector` extension.
    if dialect == "postgresql":
        # IVFFLAT requires ANALYZE of some data first, but the index can be
        # built empty. lists=100 is a sensible starting point for corpora up
        # to ~100k rows; tune later as the corpus grows.
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_knowledge_chunk_embeddings_vector "
            "ON knowledge_chunk_embeddings "
            "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        )
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_specimen_behavior_embeddings_vector "
            "ON specimen_behavior_embeddings "
            "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute(
            "DROP INDEX IF EXISTS ix_specimen_behavior_embeddings_vector"
        )
        op.execute(
            "DROP INDEX IF EXISTS ix_knowledge_chunk_embeddings_vector"
        )

    op.drop_index(
        "ix_specimen_behavior_embeddings_digest",
        table_name="specimen_behavior_embeddings",
    )
    op.drop_index(
        "ix_specimen_behavior_embeddings_specimen_id",
        table_name="specimen_behavior_embeddings",
    )
    op.drop_table("specimen_behavior_embeddings")

    op.drop_index(
        "ix_knowledge_chunk_embeddings_sha256",
        table_name="knowledge_chunk_embeddings",
    )
    op.drop_index(
        "ix_knowledge_chunk_embeddings_tenant_id",
        table_name="knowledge_chunk_embeddings",
    )
    op.drop_index(
        "ix_knowledge_chunk_embeddings_document_id",
        table_name="knowledge_chunk_embeddings",
    )
    op.drop_index(
        "ix_knowledge_chunk_embeddings_chunk_id",
        table_name="knowledge_chunk_embeddings",
    )
    op.drop_table("knowledge_chunk_embeddings")

    # Leave the vector extension installed when downgrading - other migrations
    # may rely on it. Callers who want to remove it can do so manually with
    # DROP EXTENSION IF EXISTS vector.
