"""V5 W3a — analytics.read permission.

Adds the ``analytics.read`` permission and grants it to the operator
roles that need to see the team-analytics dashboard:

- ``senior_analyst`` — needs MTTR + queue-aging to manage their own
  case load.
- ``reviewer`` — needs review-latency + queue-aging to triage what
  they pick up.
- ``lab_lead`` — superuser; receives all permissions.

Deliberately omitted from ``analyst`` and ``read_only`` so the
analytics page does not become a read-only "dashboard tour"
distraction for those roles.

Revision ID: v5a07
Revises: v5a06
Create Date: 2026-05-07
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "v5a07"
down_revision = "v5a06"
branch_labels = None
depends_on = None


PERMISSION_NAME = "analytics.read"
PERMISSION_DESCRIPTION = (
    "View team analytics dashboard (MTTR, review latency, ATT&CK drift, "
    "capability usage, queue aging)."
)
GRANT_TO_ROLES: tuple[str, ...] = (
    "senior_analyst",
    "reviewer",
    "lab_lead",
)


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
        [{"name": PERMISSION_NAME, "description": PERMISSION_DESCRIPTION}],
    )
    op.bulk_insert(
        role_perm_table,
        [
            {"role_name": role, "permission_name": PERMISSION_NAME}
            for role in GRANT_TO_ROLES
        ],
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DELETE FROM role_permissions WHERE permission_name = :p"
        ).bindparams(p=PERMISSION_NAME)
    )
    op.execute(
        sa.text(
            "DELETE FROM permissions WHERE name = :p"
        ).bindparams(p=PERMISSION_NAME)
    )
