"""P0 exact-action authorization requests and durable agent dispositions.

Revision ID: v5a08
Revises: v5a07
Create Date: 2026-08-29
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.util import column_exists, existing_tables, index_exists


revision = "v5a08"
down_revision = "v5a07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = existing_tables(bind)

    if "authorization_request_records" not in tables:
        op.create_table(
            "authorization_request_records",
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("capability", sa.String(length=80), nullable=False),
            sa.Column("scope", sa.JSON(), nullable=False),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("action_digest", sa.String(length=80), nullable=False),
            sa.Column("requester", sa.String(length=200), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("requested_ttl_seconds", sa.Integer(), nullable=True),
            sa.Column("engagement_ref", sa.Text(), nullable=True),
            sa.Column(
                "status",
                sa.String(length=20),
                nullable=False,
                server_default="pending",
            ),
            sa.Column("required_approvals", sa.Integer(), nullable=False),
            sa.Column(
                "requires_admin_approval",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column("artifact_id", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.CheckConstraint(
                "status IN ('pending', 'issued', 'rejected', 'expired')",
                name="ck_authorization_request_status",
            ),
            sa.PrimaryKeyConstraint("request_id"),
        )
        op.create_index(
            "ix_authorization_request_records_capability",
            "authorization_request_records",
            ["capability"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_request_records_action_digest",
            "authorization_request_records",
            ["action_digest"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_request_records_requester",
            "authorization_request_records",
            ["requester"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_request_records_status",
            "authorization_request_records",
            ["status"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_request_records_artifact_id",
            "authorization_request_records",
            ["artifact_id"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_requests_capability_status",
            "authorization_request_records",
            ["capability", "status"],
            unique=False,
        )

    if "authorization_decision_records" not in tables:
        op.create_table(
            "authorization_decision_records",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("request_id", sa.String(length=64), nullable=False),
            sa.Column("reviewer", sa.String(length=200), nullable=False),
            sa.Column("reviewer_roles", sa.JSON(), nullable=False),
            sa.Column("decision", sa.String(length=20), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.CheckConstraint(
                "decision IN ('approve', 'reject')",
                name="ck_authorization_decision_value",
            ),
            sa.ForeignKeyConstraint(
                ["request_id"],
                ["authorization_request_records.request_id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "request_id",
                "reviewer",
                name="uq_authorization_decision_request_reviewer",
            ),
        )
        op.create_index(
            "ix_authorization_decision_records_request_id",
            "authorization_decision_records",
            ["request_id"],
            unique=False,
        )
        op.create_index(
            "ix_authorization_decision_records_reviewer",
            "authorization_decision_records",
            ["reviewer"],
            unique=False,
        )

    if "autonomous_agent_runs" in tables:
        if not column_exists(bind, "autonomous_agent_runs", "disposition"):
            op.add_column(
                "autonomous_agent_runs",
                sa.Column(
                    "disposition",
                    sa.JSON(),
                    nullable=False,
                    server_default=sa.text("'{}'"),
                ),
            )
        if not column_exists(bind, "autonomous_agent_runs", "action_digest"):
            op.add_column(
                "autonomous_agent_runs",
                sa.Column("action_digest", sa.String(length=80), nullable=True),
            )
        if not column_exists(
            bind, "autonomous_agent_runs", "authorization_artifact_id"
        ):
            op.add_column(
                "autonomous_agent_runs",
                sa.Column(
                    "authorization_artifact_id",
                    sa.String(length=64),
                    nullable=True,
                ),
            )
        if not index_exists(
            bind, "autonomous_agent_runs", "ix_autonomous_agent_runs_action_digest"
        ):
            op.create_index(
                "ix_autonomous_agent_runs_action_digest",
                "autonomous_agent_runs",
                ["action_digest"],
                unique=False,
            )
        if not index_exists(
            bind,
            "autonomous_agent_runs",
            "ix_autonomous_agent_runs_authorization_artifact_id",
        ):
            op.create_index(
                "ix_autonomous_agent_runs_authorization_artifact_id",
                "autonomous_agent_runs",
                ["authorization_artifact_id"],
                unique=False,
            )


def downgrade() -> None:
    bind = op.get_bind()
    tables = existing_tables(bind)

    if "autonomous_agent_runs" in tables:
        if index_exists(
            bind,
            "autonomous_agent_runs",
            "ix_autonomous_agent_runs_authorization_artifact_id",
        ):
            op.drop_index(
                "ix_autonomous_agent_runs_authorization_artifact_id",
                table_name="autonomous_agent_runs",
            )
        if index_exists(
            bind, "autonomous_agent_runs", "ix_autonomous_agent_runs_action_digest"
        ):
            op.drop_index(
                "ix_autonomous_agent_runs_action_digest",
                table_name="autonomous_agent_runs",
            )
        if column_exists(
            bind, "autonomous_agent_runs", "authorization_artifact_id"
        ):
            op.drop_column("autonomous_agent_runs", "authorization_artifact_id")
        if column_exists(bind, "autonomous_agent_runs", "action_digest"):
            op.drop_column("autonomous_agent_runs", "action_digest")
        if column_exists(bind, "autonomous_agent_runs", "disposition"):
            op.drop_column("autonomous_agent_runs", "disposition")

    if "authorization_decision_records" in tables:
        op.drop_index(
            "ix_authorization_decision_records_reviewer",
            table_name="authorization_decision_records",
        )
        op.drop_index(
            "ix_authorization_decision_records_request_id",
            table_name="authorization_decision_records",
        )
        op.drop_table("authorization_decision_records")

    if "authorization_request_records" in tables:
        op.drop_index(
            "ix_authorization_requests_capability_status",
            table_name="authorization_request_records",
        )
        op.drop_index(
            "ix_authorization_request_records_artifact_id",
            table_name="authorization_request_records",
        )
        op.drop_index(
            "ix_authorization_request_records_status",
            table_name="authorization_request_records",
        )
        op.drop_index(
            "ix_authorization_request_records_requester",
            table_name="authorization_request_records",
        )
        op.drop_index(
            "ix_authorization_request_records_action_digest",
            table_name="authorization_request_records",
        )
        op.drop_index(
            "ix_authorization_request_records_capability",
            table_name="authorization_request_records",
        )
        op.drop_table("authorization_request_records")
