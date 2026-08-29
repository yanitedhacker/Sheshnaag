"""V5 W1b — worker pool fleet registry, CA key, enrollment tokens.

Three new tables. CA private key is KEK-encrypted at rest; the KEK is
derived in application code via HKDF from settings.secret_key. The
migration only stores the encrypted bytes — it never sees plaintext.

Revision ID: v5a04
Revises: v5a03
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.guards import existing_tables, index_exists


revision = "v5a04"
down_revision = "v5a03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    tables = existing_tables(bind)

    if "workers" not in tables:
        op.create_table(
            "workers",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("worker_uuid", sa.String(length=64), nullable=False),
            sa.Column("cert_fingerprint", sa.String(length=128), nullable=False),
            sa.Column("cert_pem", sa.Text(), nullable=False),
            sa.Column(
                "capability_flags",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            ),
            sa.Column(
                "state",
                sa.String(length=20),
                nullable=False,
                server_default="online",
            ),
            sa.Column("last_heartbeat", sa.DateTime(), nullable=True),
            sa.Column("enrolled_at", sa.DateTime(), nullable=False),
            sa.Column("enrolled_by", sa.String(length=200), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.UniqueConstraint("worker_uuid", name="uq_workers_uuid"),
            sa.UniqueConstraint("cert_fingerprint", name="uq_workers_cert_fp"),
        )
    if not index_exists(bind, "workers", "ix_workers_state"):
        op.create_index("ix_workers_state", "workers", ["state"], unique=False)

    if "worker_ca_keys" not in tables:
        op.create_table(
            "worker_ca_keys",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("cert_pem", sa.Text(), nullable=False),
            sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
            sa.Column("nonce", sa.LargeBinary(), nullable=False),
            sa.Column("not_before", sa.DateTime(), nullable=False),
            sa.Column("not_after", sa.DateTime(), nullable=False),
            sa.Column(
                "is_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("created_by", sa.String(length=200), nullable=False),
        )

    if "worker_enrollment_tokens" not in tables:
        op.create_table(
            "worker_enrollment_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("token_hash", sa.String(length=128), nullable=False),
            sa.Column("issued_by", sa.String(length=200), nullable=False),
            sa.Column("issued_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("consumed_at", sa.DateTime(), nullable=True),
            sa.Column("consumed_by_worker_id", sa.Integer(), nullable=True),
            sa.UniqueConstraint("token_hash", name="uq_enrollment_token_hash"),
        )
    if not index_exists(
        bind,
        "worker_enrollment_tokens",
        "ix_worker_enrollment_tokens_expires_at",
    ):
        op.create_index(
            "ix_worker_enrollment_tokens_expires_at",
            "worker_enrollment_tokens",
            ["expires_at"],
            unique=False,
        )


def downgrade() -> None:
    op.drop_index(
        "ix_worker_enrollment_tokens_expires_at",
        table_name="worker_enrollment_tokens",
    )
    op.drop_table("worker_enrollment_tokens")
    op.drop_table("worker_ca_keys")
    op.drop_index("ix_workers_state", table_name="workers")
    op.drop_table("workers")
