"""Runtime inspection helpers for idempotent Alembic upgrades."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


def _offline() -> bool:
    return bool(op.get_context().as_sql)


def existing_tables(bind) -> set[str]:
    if _offline():
        return set()
    return set(sa.inspect(bind).get_table_names())


def column_exists(bind, table: str, column: str) -> bool:
    if _offline():
        return False
    return column in {item["name"] for item in sa.inspect(bind).get_columns(table)}


def index_exists(bind, table: str, index_name: str) -> bool:
    if _offline():
        return False
    return index_name in {
        item["name"] for item in sa.inspect(bind).get_indexes(table)
    }


def table_row_count(bind, table: str) -> int:
    if _offline():
        return 0
    quoted = bind.dialect.identifier_preparer.quote(table)
    return int(bind.execute(sa.text(f"SELECT COUNT(*) FROM {quoted}")).scalar() or 0)
