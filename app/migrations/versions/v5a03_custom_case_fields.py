"""V5 W0d — per-tenant custom case fields with JSON-Schema validation.

Adds ``analysis_cases.custom_fields`` JSON column and creates the
``case_field_schemas`` table. Validation against the active schema
happens in :mod:`app.services.case_field_schema`, not at the DB layer.

Revision ID: v5a03
Revises: v5a02
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.guards import column_exists, existing_tables


revision = "v5a03"
down_revision = "v5a02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # JSON column on analysis_cases. server_default '{}' so existing
    # rows get an empty object without a backfill step.
    if not column_exists(bind, "analysis_cases", "custom_fields"):
        op.add_column(
            "analysis_cases",
            sa.Column(
                "custom_fields",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            ),
        )

    if "case_field_schemas" not in existing_tables(bind):
        op.create_table(
            "case_field_schemas",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column(
                "tenant_id",
                sa.Integer(),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("schema_version", sa.Integer(), nullable=False),
            sa.Column("schema", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("created_by", sa.String(length=200), nullable=False),
            sa.UniqueConstraint(
                "tenant_id", "schema_version", name="uq_case_field_schema_version"
            ),
        )


def downgrade() -> None:
    op.drop_table("case_field_schemas")
    op.drop_column("analysis_cases", "custom_fields")
