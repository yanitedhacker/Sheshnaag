"""V4 Phase C slice 4 — IOC pivot edges on the exposure graph.

This migration prepares :class:`~app.models.v2.ExposureGraphEdge` for the
V4 Phase C slice-4 IOC pivot vocabulary. In practice it does two things:

1. Adds composite indexes on ``(from_node_id, edge_type)`` and
   ``(to_node_id, edge_type)`` so that indicator-centric pivots (such as
   "all findings linked to this IOC") can be answered with a single range
   scan instead of a full table scan.
2. If the deployment happens to store ``edge_type`` behind a CHECK
   constraint (future-proofing; the current schema does not), expands the
   permitted vocabulary to include the five new kinds:

   - ``ioc_to_finding``
   - ``ioc_to_specimen``
   - ``ioc_to_cve``
   - ``ioc_to_asset``
   - ``ioc_cooccurs_with``

On PostgreSQL the CHECK constraint is dropped and re-added (if present).
On SQLite — which does not support ``ALTER TABLE`` against CHECK
constraints — the re-add step is skipped with a logged warning; the
application-level vocabulary in :mod:`app.services.graph_service`
(``IOC_EDGE_KINDS``) remains authoritative.

Downgrade drops the composite indexes and, on PostgreSQL, restores the
original CHECK constraint (if one was managed by this migration).
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op


# Alembic identifiers — chain directly after the pgvector embeddings slice.
revision = "v4a03"
down_revision = "v4a02"
branch_labels = None
depends_on = None


logger = logging.getLogger(__name__)


IOC_EDGE_KINDS = (
    "ioc_to_finding",
    "ioc_to_specimen",
    "ioc_to_cve",
    "ioc_to_asset",
    "ioc_cooccurs_with",
)

BASE_EDGE_KINDS = (
    "runs",
    "reachable_from",
    "exposes",
    "contains_vulnerability",
    "depends_on",
    "authenticates_to",
    "mitigated_by",
)

EDGE_TYPE_CHECK_CONSTRAINT_NAME = "ck_exposure_graph_edges_edge_type"

FROM_NODE_INDEX_NAME = "ix_exposure_graph_edges_from_node_id_edge_type"
TO_NODE_INDEX_NAME = "ix_exposure_graph_edges_to_node_id_edge_type"


def _has_check_constraint(inspector: sa.engine.reflection.Inspector, name: str) -> bool:
    try:
        checks = inspector.get_check_constraints("exposure_graph_edges")
    except NotImplementedError:
        return False
    return any(chk.get("name") == name for chk in checks)


def _existing_indexes(inspector: sa.engine.reflection.Inspector) -> set[str]:
    try:
        return {idx["name"] for idx in inspector.get_indexes("exposure_graph_edges") if idx.get("name")}
    except Exception:
        return set()


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)

    existing = _existing_indexes(inspector)

    # --- indexes ---------------------------------------------------------
    if FROM_NODE_INDEX_NAME not in existing:
        op.create_index(
            FROM_NODE_INDEX_NAME,
            "exposure_graph_edges",
            ["from_node_id", "edge_type"],
            unique=False,
        )
    if TO_NODE_INDEX_NAME not in existing:
        op.create_index(
            TO_NODE_INDEX_NAME,
            "exposure_graph_edges",
            ["to_node_id", "edge_type"],
            unique=False,
        )

    # --- CHECK constraint vocabulary -------------------------------------
    #
    # The current baseline schema stores ``edge_type`` as a plain
    # ``VARCHAR(50)`` with no CHECK constraint — the vocabulary is
    # enforced at the application layer. We still handle the case where
    # an older Postgres deployment manages a CHECK constraint via this
    # migration so that upgrades remain idempotent.
    allowed_values = BASE_EDGE_KINDS + IOC_EDGE_KINDS
    allowed_sql = ", ".join(f"'{value}'" for value in allowed_values)

    if dialect == "postgresql":
        if _has_check_constraint(inspector, EDGE_TYPE_CHECK_CONSTRAINT_NAME):
            op.execute(
                f"ALTER TABLE exposure_graph_edges "
                f"DROP CONSTRAINT {EDGE_TYPE_CHECK_CONSTRAINT_NAME}"
            )
            op.execute(
                f"ALTER TABLE exposure_graph_edges "
                f"ADD CONSTRAINT {EDGE_TYPE_CHECK_CONSTRAINT_NAME} "
                f"CHECK (edge_type IN ({allowed_sql}))"
            )
        else:
            logger.info(
                "v4a03: exposure_graph_edges has no managed CHECK constraint "
                "on edge_type; skipping vocabulary expansion"
            )
    elif dialect == "sqlite":
        # SQLite cannot ALTER a CHECK constraint in place. We intentionally
        # skip the rewrite — the application-level vocabulary in
        # app.services.graph_service.IOC_EDGE_KINDS remains the source of
        # truth for local / test environments.
        logger.warning(
            "v4a03: SQLite does not support ALTER TABLE ... CHECK; "
            "IOC edge-kind vocabulary is enforced at the application layer"
        )
    else:
        logger.info(
            "v4a03: dialect %s — skipping CHECK-constraint vocabulary rewrite",
            dialect,
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)

    existing = _existing_indexes(inspector)

    allowed_sql = ", ".join(f"'{value}'" for value in BASE_EDGE_KINDS)

    if dialect == "postgresql" and _has_check_constraint(
        inspector, EDGE_TYPE_CHECK_CONSTRAINT_NAME
    ):
        op.execute(
            f"ALTER TABLE exposure_graph_edges "
            f"DROP CONSTRAINT {EDGE_TYPE_CHECK_CONSTRAINT_NAME}"
        )
        op.execute(
            f"ALTER TABLE exposure_graph_edges "
            f"ADD CONSTRAINT {EDGE_TYPE_CHECK_CONSTRAINT_NAME} "
            f"CHECK (edge_type IN ({allowed_sql}))"
        )

    if TO_NODE_INDEX_NAME in existing:
        op.drop_index(TO_NODE_INDEX_NAME, table_name="exposure_graph_edges")
    if FROM_NODE_INDEX_NAME in existing:
        op.drop_index(FROM_NODE_INDEX_NAME, table_name="exposure_graph_edges")
