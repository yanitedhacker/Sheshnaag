"""V6 W1 — purple.replay and research.write permissions."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "v6a02"
down_revision = "v6a01"
branch_labels = None
depends_on = None

NEW_PERMISSIONS = (
    ("purple.replay", "Run purple-team ART/Caldera replay"),
    ("research.write", "Use offensive research workbench"),
)
GRANT_TO_ROLES = ("senior_analyst", "lab_lead")


def upgrade() -> None:
    permission_table = sa.table(
        "permissions",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )
    role_perm_table = sa.table(
        "role_permissions",
        sa.column("role_name", sa.String),
        sa.column("permission_name", sa.String),
    )
    op.bulk_insert(
        permission_table,
        [{"name": n, "description": d} for n, d in NEW_PERMISSIONS],
    )
    rows = [
        {"role_name": role, "permission_name": perm}
        for role in GRANT_TO_ROLES
        for perm, _ in NEW_PERMISSIONS
    ]
    op.bulk_insert(role_perm_table, rows)


def downgrade() -> None:
    for perm, _ in NEW_PERMISSIONS:
        op.execute(
            sa.text("DELETE FROM role_permissions WHERE permission_name = :p"),
            {"p": perm},
        )
        op.execute(sa.text("DELETE FROM permissions WHERE name = :p"), {"p": perm})
