"""Seed the current RBAC catalog without replacing operator-owned rows."""

from __future__ import annotations

from collections.abc import Iterable

import sqlalchemy as sa

from app.migrations.versions.v5a01_roles_permissions import (
    PERMISSIONS as V5_PERMISSIONS,
    ROLES as V5_ROLES,
    _build_role_perm_map,
)
from app.migrations.versions.v5a07_analytics_permission import (
    GRANT_TO_ROLES as ANALYTICS_GRANT_TO_ROLES,
    PERMISSION_DESCRIPTION as ANALYTICS_PERMISSION_DESCRIPTION,
    PERMISSION_NAME as ANALYTICS_PERMISSION_NAME,
)


V6_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("purple.replay", "Run purple-team ART/Caldera replay"),
    ("research.write", "Use offensive research workbench"),
)
V6_GRANT_TO_ROLES: tuple[str, ...] = ("senior_analyst", "lab_lead")


def _missing_names(connection, table, names: Iterable[str]) -> set[str]:
    expected = set(names)
    existing = set(connection.execute(sa.select(table.c.name)).scalars())
    return expected - existing


def ensure_current_rbac_catalog(connection) -> None:
    """Insert each missing current role, permission, and expected grant."""

    role_table = sa.table(
        "roles",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )
    permission_table = sa.table(
        "permissions",
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
    )
    role_permission_table = sa.table(
        "role_permissions",
        sa.column("role_name", sa.String),
        sa.column("permission_name", sa.String),
    )

    missing_roles = _missing_names(connection, role_table, (name for name, _ in V5_ROLES))
    if missing_roles:
        connection.execute(
            role_table.insert(),
            [
                {"name": name, "description": description}
                for name, description in V5_ROLES
                if name in missing_roles
            ],
        )

    current_permissions = (
        *V5_PERMISSIONS,
        (ANALYTICS_PERMISSION_NAME, ANALYTICS_PERMISSION_DESCRIPTION),
        *V6_PERMISSIONS,
    )
    missing_permissions = _missing_names(
        connection,
        permission_table,
        (name for name, _ in current_permissions),
    )
    if missing_permissions:
        connection.execute(
            permission_table.insert(),
            [
                {"name": name, "description": description}
                for name, description in current_permissions
                if name in missing_permissions
            ],
        )

    role_permission_map = {
        role: set(permissions)
        for role, permissions in _build_role_perm_map().items()
    }
    for role in ANALYTICS_GRANT_TO_ROLES:
        role_permission_map[role].add(ANALYTICS_PERMISSION_NAME)
    for role in V6_GRANT_TO_ROLES:
        role_permission_map[role].update(name for name, _ in V6_PERMISSIONS)

    expected_grants = {
        (role, permission)
        for role, permissions in role_permission_map.items()
        for permission in permissions
    }
    existing_grants = {
        (row[0], row[1])
        for row in connection.execute(
            sa.select(
                role_permission_table.c.role_name,
                role_permission_table.c.permission_name,
            )
        )
    }
    missing_grants = sorted(expected_grants - existing_grants)
    if missing_grants:
        connection.execute(
            role_permission_table.insert(),
            [
                {"role_name": role, "permission_name": permission}
                for role, permission in missing_grants
            ],
        )
