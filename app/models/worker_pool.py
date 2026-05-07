"""V5 W1b worker-pool models — fleet registry, CA key, enrollment tokens.

Three tables back the worker pool:
  - ``workers``: one row per enrolled sandbox worker (id, cert
    fingerprint, capability flags, heartbeat, state).
  - ``worker_ca_keys``: a single-row table holding the CA cert and the
    KEK-encrypted CA private key.
  - ``worker_enrollment_tokens``: short-lived single-use tokens issued
    by lab_lead so workers can prove they were authorized to join.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
)

from app.core.database import Base
from app.core.time import utc_now


class Worker(Base):
    """An enrolled sandbox-worker node."""

    __tablename__ = "workers"

    id = Column(Integer, primary_key=True, index=True)
    worker_uuid = Column(String(64), unique=True, nullable=False, index=True)
    cert_fingerprint = Column(String(128), unique=True, nullable=False, index=True)
    cert_pem = Column(Text, nullable=False)
    capability_flags = Column(JSON, default=list, nullable=False)
    state = Column(
        String(20),
        nullable=False,
        default="online",
        server_default="online",
    )  # "online" | "offline" | "draining"
    last_heartbeat = Column(DateTime, default=utc_now, nullable=True)
    enrolled_at = Column(DateTime, default=utc_now, nullable=False)
    enrolled_by = Column(String(200), nullable=False)
    notes = Column(Text, nullable=True)


class WorkerCaKey(Base):
    """Single-row holder for the worker-pool CA.

    Application code enforces "single row" — first-run code generates a
    CA only if the table is empty; rotation flow creates a new row and
    flips ``is_active``.
    """

    __tablename__ = "worker_ca_keys"

    id = Column(Integer, primary_key=True, index=True)
    cert_pem = Column(Text, nullable=False)
    encrypted_private_key = Column(LargeBinary, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    not_before = Column(DateTime, nullable=False)
    not_after = Column(DateTime, nullable=False)
    is_active = Column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    created_at = Column(DateTime, default=utc_now)
    created_by = Column(String(200), nullable=False)


class WorkerEnrollmentToken(Base):
    """Single-use enrollment token authorizing one worker to join the fleet."""

    __tablename__ = "worker_enrollment_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    issued_by = Column(String(200), nullable=False)
    issued_at = Column(DateTime, default=utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    consumed_at = Column(DateTime, nullable=True)
    consumed_by_worker_id = Column(Integer, nullable=True)
