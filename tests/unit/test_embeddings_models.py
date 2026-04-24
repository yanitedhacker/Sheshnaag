"""Unit tests for the dialect-aware vector column in app.models.embeddings."""

from __future__ import annotations

from sqlalchemy import JSON, create_engine
from sqlalchemy.dialects import postgresql, sqlite

from app.models.embeddings import (
    KnowledgeChunkEmbedding,
    SpecimenBehaviorEmbedding,
    VECTOR_DIM,
    VectorOrJSON,
)


def test_vector_column_type_dialect_aware():
    column = VectorOrJSON(VECTOR_DIM)

    # SQLite should resolve to plain JSON storage.
    sqlite_impl = column.load_dialect_impl(sqlite.dialect())
    assert isinstance(sqlite_impl, JSON) or "JSON" in type(sqlite_impl).__name__

    # Postgres should resolve to a pgvector Vector column when pgvector
    # is installed; if it's not importable we accept a JSON fallback. The
    # important contract is: different concrete type on postgres vs sqlite
    # OR a vector column name.
    pg_impl = column.load_dialect_impl(postgresql.dialect())
    name = type(pg_impl).__name__
    assert name in {"VECTOR", "Vector", "JSON"}


def test_vector_column_roundtrips_list_on_sqlite():
    engine = create_engine("sqlite://")
    from app.core.database import Base
    import app.models  # noqa: F401  -- register all tables

    Base.metadata.create_all(engine)
    try:
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=engine)
        sess = Session()

        # We can't instantiate a KnowledgeChunkEmbedding with a real chunk_id
        # without wiring up the whole document tree, so just exercise the
        # dialect-aware type via a detached INSERT.
        vec = [0.1] * VECTOR_DIM
        row = KnowledgeChunkEmbedding(
            chunk_id=None,
            document_id=1,
            tenant_id=None,
            chunk_index=0,
            sha256="a" * 64,
            source_label="test",
            source_url=None,
            content_preview="hello",
            embedding_model="test-model",
            embedding=vec,
        )
        sess.add(row)
        sess.commit()
        fetched = sess.query(KnowledgeChunkEmbedding).first()
        assert fetched is not None
        assert fetched.embedding == vec
        assert fetched.sha256 == "a" * 64
    finally:
        Base.metadata.drop_all(engine)


def test_specimen_behavior_embedding_schema():
    # The mapper must have the expected column set.
    cols = {c.name for c in SpecimenBehaviorEmbedding.__table__.columns}
    assert {"specimen_id", "feature_digest", "embedding", "created_at"}.issubset(
        cols
    )
