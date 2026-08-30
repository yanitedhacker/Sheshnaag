"""Repair legacy tenant roles and enforce the V5 role vocabulary."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from app.migrations.versions.v5a01_roles_permissions import (
    LEGACY_ROLE_MAP,
    VALID_ROLE_NAMES,
)


revision = "v6a03"
down_revision = "v6a02"
branch_labels = None
depends_on = None

CONSTRAINT_NAME = "ck_tenant_memberships_role_v5_valid_v6a03"


def _repair_legacy_roles() -> None:
    membership = sa.table(
        "tenant_memberships",
        sa.column("role", sa.String),
    )
    for legacy, current in LEGACY_ROLE_MAP.items():
        if legacy == current:
            continue
        op.execute(
            membership.update()
            .where(membership.c.role == legacy)
            .values(role=current)
        )
    op.execute(
        membership.update()
        .where(membership.c.role.not_in(VALID_ROLE_NAMES))
        .values(role="analyst")
    )


def upgrade() -> None:
    if op.get_context().as_sql:
        _repair_legacy_roles()
        op.create_check_constraint(
            CONSTRAINT_NAME,
            "tenant_memberships",
            "role IN ('read_only', 'analyst', 'senior_analyst', 'reviewer', 'lab_lead')",
        )
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "tenant_memberships" not in inspector.get_table_names():
        raise RuntimeError("tenant_memberships_table_required")

    _repair_legacy_roles()
    if bind.dialect.name == "postgresql":
        existing = {
            item["name"]
            for item in inspector.get_check_constraints("tenant_memberships")
        }
        if CONSTRAINT_NAME not in existing:
            op.create_check_constraint(
                CONSTRAINT_NAME,
                "tenant_memberships",
                "role IN ('read_only', 'analyst', 'senior_analyst', 'reviewer', 'lab_lead')",
            )


def downgrade() -> None:
    if op.get_context().as_sql:
        op.drop_constraint(CONSTRAINT_NAME, "tenant_memberships", type_="check")
        return

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    inspector = sa.inspect(bind)
    existing = {
        item["name"]
        for item in inspector.get_check_constraints("tenant_memberships")
    }
    if CONSTRAINT_NAME in existing:
        op.drop_constraint(CONSTRAINT_NAME, "tenant_memberships", type_="check")
