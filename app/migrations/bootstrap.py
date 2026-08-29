"""Helpers for creating a current-schema snapshot on an empty database."""

from __future__ import annotations

from sqlalchemy import text


def create_current_schema_snapshot(connection, metadata) -> None:
    """Create database prerequisites, then create all current application tables."""

    if connection.dialect.name == "postgresql":
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    metadata.create_all(bind=connection)
