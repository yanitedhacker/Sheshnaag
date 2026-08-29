"""V5 W1a — OIDC provider configuration catalog.

One row per registered IdP (Keycloak, Authentik, Auth0). Plaintext
client secrets never persist — we store an env-var name or KMS URI and
resolve at runtime.

Revision ID: v5a05
Revises: v5a04
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.guards import existing_tables


revision = "v5a05"
down_revision = "v5a04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "oidc_providers" in existing_tables(op.get_bind()):
        return

    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("issuer_url", sa.String(length=500), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret_ref", sa.String(length=255), nullable=False),
        sa.Column("redirect_uri", sa.String(length=500), nullable=False),
        sa.Column(
            "scopes",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "claim_mappings",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "default_tenant_id",
            sa.Integer(),
            sa.ForeignKey("tenants.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("name", name="uq_oidc_providers_name"),
    )


def downgrade() -> None:
    op.drop_table("oidc_providers")
