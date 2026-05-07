"""V5 W0a — RBAC roles, permissions, role-permission mappings.

Adds the catalog of named roles + permissions backing the V5 "Team Lab"
RBAC. The user→role binding stays in ``tenant_memberships.role`` (no
new ``user_roles`` table). Existing legacy values in that column are
backfilled to one of the five new role names.

Revision ID: v5a01
Revises: v4a04
Create Date: 2026-05-07
"""

from __future__ import annotations

import logging

from alembic import op
import sqlalchemy as sa


revision = "v5a01"
down_revision = "v4a04"
branch_labels = None
depends_on = None


logger = logging.getLogger(__name__)


# 5 V5 roles. Order matters: the seed loop preserves it.
ROLES: list[tuple[str, str]] = [
    ("read_only", "View-only access across the lab. No write or review actions."),
    ("analyst", "Daily detonation, triage, and intel work."),
    ("senior_analyst", "Analyst privileges plus recipe authoring and autonomous-agent runs."),
    ("reviewer", "Reviewer-only inbox: authorization, defang, disclosure approvals."),
    ("lab_lead", "Superuser. Owns role assignment, policy edits, and emergency overrides."),
]


# Permission catalog. Slugs follow the route audit at
# ``docs/runbooks/v5/route_nav_audit.md``. Adding a permission is a code
# change + migration, not an env override.
PERMISSIONS: list[tuple[str, str]] = [
    ("intel.read", "View intel dashboard."),
    ("review.read", "View review queue."),
    ("candidates.read", "View candidate queue."),
    ("recipes.write", "Author or edit detonation recipes."),
    ("runs.read", "View run console + logs."),
    ("authorization.review", "Approve / deny capability authorization requests."),
    ("attack.read", "View ATT&CK coverage."),
    ("cases.read", "View analysis cases + case graph."),
    ("autonomous.run", "Trigger autonomous analyst agent runs."),
    ("evidence.read", "View evidence explorer."),
    ("artifacts.write", "Author or edit analysis artifacts."),
    ("provenance.read", "View provenance center."),
    ("ledger.read", "View analyst ledger."),
    ("disclosure.write", "Compose and sign disclosure bundles."),
    ("specimens.write", "Submit or edit specimen intake."),
    ("profiles.write", "Author or edit sandbox profiles."),
    ("findings.read", "View behavior findings."),
    ("indicators.write", "Author or edit indicator artifacts."),
    ("prevention.write", "Author or edit prevention artifacts."),
    ("defang.review", "Approve defang queue actions."),
    ("reports.read", "View malware reports."),
    ("ai_sessions.read", "View AI session drafts."),
    ("policy.write", "Edit policy center / capability policy."),
    ("admin.roles.assign", "Assign roles to users (lab_lead only by default)."),
]


# Role × permission map, derived directly from the V5 frontend route
# audit at ``docs/runbooks/v5/route_nav_audit.md``. Permissions are
# enumerated explicitly per role rather than inherited via *.read globs;
# the route audit shows that not every *.read permission is granted to
# read_only (e.g. ``review.read``, ``ledger.read``, ``ai_sessions.read``
# are deliberately scoped to operator roles).
def _build_role_perm_map() -> dict[str, set[str]]:
    # Pages the audit marks "read_only" allowed: intel, runs, attack,
    # cases (graph + cases), evidence, provenance, findings, reports.
    read_only_perms: set[str] = {
        "intel.read",
        "runs.read",
        "attack.read",
        "cases.read",
        "evidence.read",
        "provenance.read",
        "findings.read",
        "reports.read",
    }

    analyst_perms: set[str] = read_only_perms | {
        "review.read",
        "candidates.read",
        "specimens.write",
        "indicators.write",
        "ai_sessions.read",
    }

    senior_analyst_perms: set[str] = analyst_perms | {
        "recipes.write",
        "artifacts.write",
        "profiles.write",
        "prevention.write",
        "autonomous.run",
        "ledger.read",
    }

    reviewer_perms: set[str] = read_only_perms | {
        "review.read",
        "candidates.read",
        "authorization.review",
        "defang.review",
        "disclosure.write",
        "ai_sessions.read",
        "ledger.read",
    }

    lab_lead_perms: set[str] = {p for p, _ in PERMISSIONS}  # superuser

    return {
        "read_only": read_only_perms,
        "analyst": analyst_perms,
        "senior_analyst": senior_analyst_perms,
        "reviewer": reviewer_perms,
        "lab_lead": lab_lead_perms,
    }


# Mapping from legacy ``tenant_memberships.role`` strings to the new
# V5 role vocabulary. Anything not in this dict falls back to "analyst"
# (the safest default that preserves write capability without granting
# review power).
LEGACY_ROLE_MAP: dict[str, str] = {
    "viewer": "read_only",
    "read_only": "read_only",
    "analyst": "analyst",
    "senior": "senior_analyst",
    "senior_analyst": "senior_analyst",
    "reviewer": "reviewer",
    "approver": "reviewer",
    "admin": "lab_lead",
    "owner": "lab_lead",
    "lab_lead": "lab_lead",
}


VALID_ROLE_NAMES = tuple(name for name, _ in ROLES)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("name", sa.String(length=50), primary_key=True, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "permissions",
        sa.Column("name", sa.String(length=80), primary_key=True, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "role_name",
            sa.String(length=50),
            sa.ForeignKey("roles.name", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "permission_name",
            sa.String(length=80),
            sa.ForeignKey("permissions.name", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # Seed roles
    bind = op.get_bind()
    now_expr = sa.func.now()

    role_table = sa.table(
        "roles",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("created_at", sa.DateTime),
    )
    permission_table = sa.table(
        "permissions",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("created_at", sa.DateTime),
    )
    role_perm_table = sa.table(
        "role_permissions",
        sa.column("role_name", sa.String),
        sa.column("permission_name", sa.String),
        sa.column("created_at", sa.DateTime),
    )

    op.bulk_insert(
        role_table,
        [{"name": name, "description": desc} for name, desc in ROLES],
    )
    op.bulk_insert(
        permission_table,
        [{"name": name, "description": desc} for name, desc in PERMISSIONS],
    )

    role_perm_map = _build_role_perm_map()
    op.bulk_insert(
        role_perm_table,
        [
            {"role_name": role, "permission_name": perm}
            for role, perms in role_perm_map.items()
            for perm in sorted(perms)
        ],
    )

    # Backfill + CHECK constraint only run in online mode. In offline
    # (``alembic upgrade --sql``) the bind is a MockConnection that does
    # not support reflection; the operator running --sql wants raw DDL,
    # not introspected migrations, so skipping is correct.
    if op.get_context().as_sql:
        return

    inspector = sa.inspect(bind)
    if "tenant_memberships" in inspector.get_table_names():
        for legacy, new in LEGACY_ROLE_MAP.items():
            op.execute(
                sa.text(
                    "UPDATE tenant_memberships SET role = :new "
                    "WHERE role = :legacy"
                ).bindparams(legacy=legacy, new=new)
            )
        # Anything still not in the new vocabulary becomes "analyst".
        valid_list = "', '".join(VALID_ROLE_NAMES)
        op.execute(
            sa.text(
                f"UPDATE tenant_memberships SET role = 'analyst' "
                f"WHERE role NOT IN ('{valid_list}')"
            )
        )

    # Postgres-only: add a CHECK constraint on tenant_memberships.role.
    # SQLite skips because adding CHECK to an existing column requires a
    # full table rebuild and dev/test SQLite is regenerated frequently.
    dialect = bind.dialect.name
    if dialect == "postgresql" and "tenant_memberships" in inspector.get_table_names():
        valid_list = ", ".join(f"'{r}'" for r in VALID_ROLE_NAMES)
        op.execute(
            f"ALTER TABLE tenant_memberships "
            f"ADD CONSTRAINT ck_tenant_memberships_role_valid "
            f"CHECK (role IN ({valid_list}))"
        )


def downgrade() -> None:
    if not op.get_context().as_sql:
        bind = op.get_bind()
        inspector = sa.inspect(bind)
        dialect = bind.dialect.name

        if dialect == "postgresql" and "tenant_memberships" in inspector.get_table_names():
            op.execute(
                "ALTER TABLE tenant_memberships "
                "DROP CONSTRAINT IF EXISTS ck_tenant_memberships_role_valid"
            )

        # Best-effort: revert all V5 role values to the v2-era 'viewer'
        # default. The original values were lossy because we mapped many
        # legacy values into a single new role; we cannot restore the
        # pre-migration distribution. This is intentional and documented.
        if "tenant_memberships" in inspector.get_table_names():
            op.execute(
                sa.text("UPDATE tenant_memberships SET role = 'viewer'")
            )

    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
