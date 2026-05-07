"""V5 RBAC service — role / permission checks for FastAPI deps.

Stateless reader over the ``roles``, ``permissions``, and
``role_permissions`` tables seeded by the v5a01 migration. The user→role
binding stays in ``tenant_memberships.role`` (per-tenant); this service
answers "does role X have permission Y?".
"""

from __future__ import annotations

from typing import Iterable, List, Set

from sqlalchemy.orm import Session

from app.models.rbac import Permission, Role, RolePermission


class RbacService:
    """Read-only RBAC evaluator. Caches role→permission set per instance."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._cache: dict[str, Set[str]] = {}

    def has_permission(self, role_name: str, permission_name: str) -> bool:
        """Return True iff the named role grants the named permission."""
        return permission_name in self._permissions_for(role_name)

    def has_any_permission(
        self, role_names: Iterable[str], permission_name: str
    ) -> bool:
        """Return True iff any of the given roles grants the permission.

        Useful when a user holds multiple memberships across tenants and
        we want to allow if *any* role grants the action.
        """
        return any(self.has_permission(r, permission_name) for r in role_names)

    def permissions_for_role(self, role_name: str) -> List[str]:
        """Return the sorted list of permissions granted to the role."""
        return sorted(self._permissions_for(role_name))

    def list_roles(self) -> List[str]:
        return [
            r.name
            for r in self._session.query(Role).order_by(Role.name).all()
        ]

    def list_permissions(self) -> List[str]:
        return [
            p.name
            for p in self._session.query(Permission)
            .order_by(Permission.name)
            .all()
        ]

    def validate_role_name(self, role_name: str) -> bool:
        """Return True iff ``role_name`` is in the role catalog."""
        return (
            self._session.query(Role).filter_by(name=role_name).first()
            is not None
        )

    def _permissions_for(self, role_name: str) -> Set[str]:
        if role_name in self._cache:
            return self._cache[role_name]
        rows = (
            self._session.query(RolePermission.permission_name)
            .filter_by(role_name=role_name)
            .all()
        )
        out = {row[0] for row in rows}
        self._cache[role_name] = out
        return out
