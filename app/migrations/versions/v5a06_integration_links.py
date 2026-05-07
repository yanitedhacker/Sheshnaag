"""V5 W2b — chat-platform <-> case integration links.

One row per (case_id, provider, external_id) — lets an inbound webhook
event identify which Sheshnaag case it's about. ``provider`` is one of
``slack`` / ``linear`` / ``jira``; ``external_id`` is the chat-platform-
side identifier (Slack message ts, Linear issue id, JIRA issue key).

Revision ID: v5a06
Revises: v5a05
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "v5a06"
down_revision = "v5a05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_integration_links",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "case_id",
            sa.Integer(),
            sa.ForeignKey("analysis_cases.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column(
            "metadata",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.UniqueConstraint(
            "provider",
            "external_id",
            name="uq_case_integration_provider_external",
        ),
    )
    op.create_index(
        "ix_case_integration_links_provider",
        "case_integration_links",
        ["provider"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_case_integration_links_provider",
        table_name="case_integration_links",
    )
    op.drop_table("case_integration_links")
