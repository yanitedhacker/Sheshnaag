"""Unit tests for the V4 Merkle-chained audit log."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
import app.models  # noqa: F401
from app.models.capability import AuditLogEntry, AuthorizationArtifact
from app.services.capability_policy import (
    CAPABILITIES,
    CapabilityPolicy,
    GENESIS_HASH,
    HmacDevSigner,
    IssuanceRequest,
    Reviewer,
    canonical_json,
)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    AuthorizationArtifact.__table__.create(engine)
    AuditLogEntry.__table__.create(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


@pytest.fixture()
def policy(session):
    return CapabilityPolicy(session, signer=HmacDevSigner(key=b"audit-chain-key"))


def _issue_and_exercise(policy):
    request = IssuanceRequest(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        requester="alice@example.com",
        reason="chain-test",
    )
    artifact = policy.issue(request, [Reviewer("bob@example.com", "approve")])
    policy.evaluate(
        capability="dynamic_detonation",
        scope={"tenant_id": 1},
        actor="alice@example.com",
    )
    policy.revoke(artifact.artifact_id, actor="bob@example.com", reason="done")
    return artifact


def test_audit_chain_hash_linked(policy, session):
    _issue_and_exercise(policy)

    rows = session.execute(
        select(AuditLogEntry).order_by(AuditLogEntry.idx.asc())
    ).scalars().all()
    assert len(rows) >= 4  # issue + approve + exercise + revoke

    previous = GENESIS_HASH
    for row in rows:
        assert bytes(row.previous_hash) == previous
        previous = bytes(row.entry_hash)


def test_audit_chain_tamper_detected(policy, session):
    _issue_and_exercise(policy)

    # Tamper with an earlier row — flip a byte in its scope JSON.
    victim = session.execute(
        select(AuditLogEntry).order_by(AuditLogEntry.idx.asc()).limit(1)
    ).scalars().first()
    original_scope = dict(victim.scope or {})
    victim.scope = {**original_scope, "tenant_id": 999}
    session.flush()

    result = policy.verify_chain()
    assert result.ok is False
    assert result.first_bad_idx == int(victim.idx)
    assert result.reason in {"entry_hash_mismatch", "signature_invalid"}


def test_audit_chain_signature_verifies(policy, session):
    _issue_and_exercise(policy)

    result = policy.verify_chain()
    assert result.ok is True
    assert result.first_bad_idx is None
    assert result.last_verified_idx >= 0
    assert result.reason == "ok"
