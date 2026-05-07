"""V5 RBAC models — roles, permissions, role-permission links.

These three tables back the V5 "Team Lab" role-based access control.
The user→role binding stays in the existing ``tenant_memberships.role``
column (no new ``user_roles`` table); these new tables describe the
*role catalog* and the *role→permission* mapping.
"""

from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, String, Text

from app.core.database import Base
from app.core.time import utc_now


class Role(Base):
    """Named role in the V5 RBAC catalog (e.g. analyst, lab_lead)."""

    __tablename__ = "roles"

    name = Column(String(50), primary_key=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)


class Permission(Base):
    """Named permission slug (e.g. intel.read, policy.write)."""

    __tablename__ = "permissions"

    name = Column(String(80), primary_key=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)


class RolePermission(Base):
    """Many-to-many link between roles and permissions."""

    __tablename__ = "role_permissions"

    role_name = Column(
        String(50),
        ForeignKey("roles.name", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_name = Column(
        String(80),
        ForeignKey("permissions.name", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at = Column(DateTime, default=utc_now)
