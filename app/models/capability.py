"""V4 capability-policy domain models.

Backs the capability-policy engine with:

- ``AuthorizationArtifact`` — the signed, scoped, time-bound permission slip a
  capability requires before it can be exercised.
- ``AuditLogEntry`` — a row in the Merkle-chained append-only audit log that
  records every issuance, approval, exercise, denial, and revocation.

These models are intentionally self-contained: the capability-policy engine is
the only subsystem that mutates these tables. The Postgres migration installs
an append-only trigger on ``audit_log_entries``; the engine never issues UPDATE
or DELETE against that table.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)

from app.core.database import Base
from app.core.time import utc_now


class AuthorizationArtifact(Base):
    """Signed authorization artifact that unlocks a capability for a scope."""

    __tablename__ = "authorization_artifacts"
    __table_args__ = (
        Index(
            "ix_authorization_artifacts_active",
            "capability",
            "expires_at",
            "revoked_at",
        ),
    )

    artifact_id = Column(String(64), primary_key=True)
    schema_version = Column(String(16), nullable=False, default="v4.1")
    capability = Column(String(80), nullable=False, index=True)
    scope = Column(JSON, nullable=False, default=dict)
    requester = Column(JSON, nullable=False, default=dict)
    reviewers = Column(JSON, nullable=False, default=list)
    issued_at = Column(DateTime, nullable=False, default=utc_now)
    expires_at = Column(DateTime, nullable=False)
    nonce = Column(String(128), nullable=False)
    previous_audit_hash = Column(LargeBinary, nullable=False)
    signer_cert = Column(LargeBinary, nullable=False)
    signature = Column(LargeBinary, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(200), nullable=True)
    revoke_reason = Column(Text, nullable=True)


class AuthorizationRequestRecord(Base):
    """Pending request for one server-derived exact action."""

    __tablename__ = "authorization_request_records"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'issued', 'rejected', 'expired')",
            name="ck_authorization_request_status",
        ),
        Index(
            "ix_authorization_requests_capability_status",
            "capability",
            "status",
        ),
    )

    request_id = Column(String(64), primary_key=True)
    capability = Column(String(80), nullable=False, index=True)
    scope = Column(JSON, nullable=False, default=dict)
    action = Column(String(80), nullable=False)
    action_digest = Column(String(80), nullable=False, index=True)
    requester = Column(String(200), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    requested_ttl_seconds = Column(Integer, nullable=True)
    engagement_ref = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="pending", index=True)
    required_approvals = Column(Integer, nullable=False)
    requires_admin_approval = Column(Boolean, nullable=False, default=False)
    artifact_id = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=utc_now)
    expires_at = Column(DateTime, nullable=False)
    resolved_at = Column(DateTime, nullable=True)


class AuthorizationDecisionRecord(Base):
    """Immutable reviewer decision for a pending authorization request."""

    __tablename__ = "authorization_decision_records"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('approve', 'reject')",
            name="ck_authorization_decision_value",
        ),
        UniqueConstraint(
            "request_id",
            "reviewer",
            name="uq_authorization_decision_request_reviewer",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(
        String(64),
        ForeignKey("authorization_request_records.request_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reviewer = Column(String(200), nullable=False, index=True)
    reviewer_roles = Column(JSON, nullable=False, default=list)
    decision = Column(String(20), nullable=False)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utc_now)


class AuditLogEntry(Base):
    """Merkle-chained append-only audit log entry."""

    __tablename__ = "audit_log_entries"

    idx = Column(BigInteger, primary_key=True, autoincrement=True)
    previous_hash = Column(LargeBinary, nullable=False)
    entry_hash = Column(LargeBinary, nullable=False)
    actor = Column(String(200), nullable=False)
    action = Column(String(40), nullable=False, index=True)
    capability = Column(String(80), nullable=False, index=True)
    artifact_id = Column(String(64), nullable=True, index=True)
    scope = Column(JSON, nullable=False, default=dict)
    payload = Column(JSON, nullable=False, default=dict)
    signed_at = Column(DateTime, nullable=False, default=utc_now)
    signer_cert = Column(LargeBinary, nullable=True)
    signature = Column(LargeBinary, nullable=True)
