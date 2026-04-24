"""Sheshnaag V4 Phase A Slice 2 — capability policy and Merkle audit log.

Revision ID: v4a01
Revises: 20260409_0001
Create Date: 2026-04-24
"""

from __future__ import annotations

import logging

from alembic import op
import sqlalchemy as sa


revision = "v4a01"
down_revision = "20260409_0001"
branch_labels = None
depends_on = None


logger = logging.getLogger(__name__)


APPEND_ONLY_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION sheshnaag_audit_log_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log_entries is append-only (no % allowed)', TG_OP
        USING ERRCODE = 'check_violation';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_entries_append_only ON audit_log_entries;

CREATE TRIGGER trg_audit_log_entries_append_only
BEFORE UPDATE OR DELETE ON audit_log_entries
FOR EACH ROW EXECUTE FUNCTION sheshnaag_audit_log_append_only();
"""


DROP_APPEND_ONLY_TRIGGER_SQL = """
DROP TRIGGER IF EXISTS trg_audit_log_entries_append_only ON audit_log_entries;
DROP FUNCTION IF EXISTS sheshnaag_audit_log_append_only();
"""


def upgrade() -> None:
    op.create_table(
        "authorization_artifacts",
        sa.Column("artifact_id", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("capability", sa.String(length=80), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("requester", sa.JSON(), nullable=False),
        sa.Column("reviewers", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("previous_audit_hash", sa.LargeBinary(), nullable=False),
        sa.Column("signer_cert", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(length=200), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("artifact_id"),
    )
    op.create_index(
        "ix_authorization_artifacts_capability",
        "authorization_artifacts",
        ["capability"],
        unique=False,
    )
    op.create_index(
        "ix_authorization_artifacts_active",
        "authorization_artifacts",
        ["capability", "expires_at", "revoked_at"],
        unique=False,
    )

    op.create_table(
        "audit_log_entries",
        sa.Column("idx", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("previous_hash", sa.LargeBinary(), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("capability", sa.String(length=80), nullable=False),
        sa.Column("artifact_id", sa.String(length=64), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("signed_at", sa.DateTime(), nullable=False),
        sa.Column("signer_cert", sa.LargeBinary(), nullable=True),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.PrimaryKeyConstraint("idx"),
    )
    op.create_index(
        "ix_audit_log_entries_action",
        "audit_log_entries",
        ["action"],
        unique=False,
    )
    op.create_index(
        "ix_audit_log_entries_capability",
        "audit_log_entries",
        ["capability"],
        unique=False,
    )
    op.create_index(
        "ix_audit_log_entries_artifact_id",
        "audit_log_entries",
        ["artifact_id"],
        unique=False,
    )

    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else op.get_context().dialect.name
    if dialect == "postgresql":
        op.execute(APPEND_ONLY_TRIGGER_SQL)
    else:
        logger.warning(
            "audit_log_entries append-only trigger is Postgres-only; "
            "dialect=%s will not enforce append-only at the DB layer.",
            dialect,
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name if bind is not None else op.get_context().dialect.name
    if dialect == "postgresql":
        op.execute(DROP_APPEND_ONLY_TRIGGER_SQL)

    op.drop_index("ix_audit_log_entries_artifact_id", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_capability", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_action", table_name="audit_log_entries")
    op.drop_table("audit_log_entries")

    op.drop_index(
        "ix_authorization_artifacts_active", table_name="authorization_artifacts"
    )
    op.drop_index(
        "ix_authorization_artifacts_capability", table_name="authorization_artifacts"
    )
    op.drop_table("authorization_artifacts")
