"""V5 W0b — case lifecycle state machine.

Adds three columns to ``analysis_cases`` (``lifecycle_state``,
``state_changed_at``, ``state_changed_by``) and creates the
``case_state_transitions`` audit table. Backfills ``lifecycle_state``
from the existing ``status`` string. The ``status`` column is preserved
for one cycle so V4 readers continue to work; V6 will drop it.

Revision ID: v5a02
Revises: v5a01
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.guards import column_exists, existing_tables, index_exists


revision = "v5a02"
down_revision = "v5a01"
branch_labels = None
depends_on = None


# Mapping from pre-V5 ``status`` strings into the V5 lifecycle vocabulary.
LEGACY_STATUS_MAP: dict[str, str] = {
    "open": "triage",
    "triage": "triage",
    "analyzing": "analysis",
    "in_progress": "analysis",
    "analysis": "analysis",
    "in_review": "review",
    "review": "review",
    "pending_review": "review",
    "ready_to_ship": "ready_to_ship",
    "ready": "ready_to_ship",
    "shipped": "shipped",
    "published": "shipped",
    "closed": "archived",
    "archived": "archived",
}


VALID_LIFECYCLE_STATES = (
    "triage",
    "analysis",
    "review",
    "ready_to_ship",
    "shipped",
    "archived",
)


def upgrade() -> None:
    bind = op.get_bind()

    # Add the 3 new columns to analysis_cases. Use server_default so
    # existing rows get a value without needing UPDATE before the
    # backfill runs.
    if not column_exists(bind, "analysis_cases", "lifecycle_state"):
        op.add_column(
            "analysis_cases",
            sa.Column(
                "lifecycle_state",
                sa.String(length=40),
                nullable=False,
                server_default="triage",
            ),
        )
    if not column_exists(bind, "analysis_cases", "state_changed_at"):
        op.add_column(
            "analysis_cases",
            sa.Column("state_changed_at", sa.DateTime(), nullable=True),
        )
    if not column_exists(bind, "analysis_cases", "state_changed_by"):
        op.add_column(
            "analysis_cases",
            sa.Column("state_changed_by", sa.String(length=200), nullable=True),
        )

    if "case_state_transitions" not in existing_tables(bind):
        op.create_table(
            "case_state_transitions",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "case_id",
                sa.Integer(),
                sa.ForeignKey("analysis_cases.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("from_state", sa.String(length=40), nullable=False),
            sa.Column("to_state", sa.String(length=40), nullable=False),
            sa.Column("actor", sa.String(length=200), nullable=False),
            sa.Column("role_at_transition", sa.String(length=50), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("occurred_at", sa.DateTime(), nullable=False),
        )
    if not index_exists(
        bind,
        "case_state_transitions",
        "ix_case_state_transitions_occurred_at",
    ):
        op.create_index(
            "ix_case_state_transitions_occurred_at",
            "case_state_transitions",
            ["occurred_at"],
            unique=False,
        )

    if op.get_context().as_sql:
        return

    # Backfill lifecycle_state from the existing status column.
    for legacy, new in LEGACY_STATUS_MAP.items():
        op.execute(
            sa.text(
                "UPDATE analysis_cases SET lifecycle_state = :new "
                "WHERE status = :legacy"
            ).bindparams(legacy=legacy, new=new)
        )
    # Anything not matched falls through with the server_default 'triage'.
    valid_list = "', '".join(VALID_LIFECYCLE_STATES)
    op.execute(
        sa.text(
            f"UPDATE analysis_cases SET lifecycle_state = 'triage' "
            f"WHERE lifecycle_state NOT IN ('{valid_list}')"
        )
    )

    # Postgres-only CHECK on lifecycle_state. SQLite skipped (cost of
    # rebuilding the table on add-CHECK is not worth it for dev/test).
    dialect = bind.dialect.name
    if dialect == "postgresql":
        valid_pg_list = ", ".join(f"'{s}'" for s in VALID_LIFECYCLE_STATES)
        op.execute(
            f"ALTER TABLE analysis_cases "
            f"ADD CONSTRAINT ck_analysis_cases_lifecycle_state_valid "
            f"CHECK (lifecycle_state IN ({valid_pg_list}))"
        )


def downgrade() -> None:
    if not op.get_context().as_sql:
        bind = op.get_bind()
        if bind.dialect.name == "postgresql":
            op.execute(
                "ALTER TABLE analysis_cases "
                "DROP CONSTRAINT IF EXISTS ck_analysis_cases_lifecycle_state_valid"
            )

    op.drop_index(
        "ix_case_state_transitions_occurred_at",
        table_name="case_state_transitions",
    )
    op.drop_table("case_state_transitions")
    op.drop_column("analysis_cases", "state_changed_by")
    op.drop_column("analysis_cases", "state_changed_at")
    op.drop_column("analysis_cases", "lifecycle_state")
