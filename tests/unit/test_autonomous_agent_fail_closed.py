"""Fail-closed tests for the autonomous-agent authorization boundary."""

from __future__ import annotations

import importlib

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.capability import AuditLogEntry, AuthorizationArtifact
from app.models.sheshnaag import AutonomousAgentRun
from app.models.v2 import Tenant
from app.services.autonomous_agent import AgentPersistenceError, AutonomousAgent


class RecordingAI:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, **kwargs):
        self.calls += 1
        return {"text": "This call must not happen for a denied run."}


class RecordingBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def publish(self, channel: str, payload: dict) -> None:
        self.events.append((channel, payload))


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Tenant.__table__.create(engine)
    AuthorizationArtifact.__table__.create(engine)
    AuditLogEntry.__table__.create(engine)
    AutonomousAgentRun.__table__.create(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    sess = Session()
    try:
        yield sess
    finally:
        sess.close()
        engine.dispose()


@pytest.fixture()
def tenant(session):
    row = Tenant(slug="p0-agent", name="P0 Agent")
    session.add(row)
    session.flush()
    return row


def _fail_if_tool_runs(*args, **kwargs):
    pytest.fail("authorization denial must stop before the first agent tool")


def test_policy_exception_denies_before_tools_ai_or_events(
    monkeypatch,
    session,
    tenant,
):
    ai = RecordingAI()
    bus = RecordingBus()
    agent = AutonomousAgent(session, ai=ai, event_bus=bus)
    policy_module = importlib.import_module("app.services.capability_policy")
    monkeypatch.setattr(
        policy_module.CapabilityPolicy,
        "evaluate",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("policy offline")),
    )
    monkeypatch.setattr(agent, "_tool_attack_summary", _fail_if_tool_runs)

    run = agent.run(
        tenant,
        goal="Review the exact case without executing live actions.",
        actor="analyst@example.com",
        case_id=None,
        max_steps=3,
    )
    session.commit()

    assert run.status == "denied"
    assert run.reason == "policy_unavailable:RuntimeError"
    assert run.disposition == {
        "code": "denied_policy_unavailable",
        "message": "Authorization policy was unavailable. The action did not run.",
        "retryable": True,
        "policy_reason": "policy_unavailable:RuntimeError",
    }
    assert run.steps == []
    assert ai.calls == 0
    assert bus.events == []
    durable = session.query(AutonomousAgentRun).filter_by(run_id=run.run_id).one()
    assert durable.status == "denied"
    assert durable.disposition == run.disposition
    assert durable.action_digest == run.action_digest


def test_no_artifact_denies_before_tools_ai_or_events(
    monkeypatch,
    session,
    tenant,
):
    ai = RecordingAI()
    bus = RecordingBus()
    agent = AutonomousAgent(session, ai=ai, event_bus=bus)
    monkeypatch.setattr(agent, "_tool_attack_summary", _fail_if_tool_runs)

    run = agent.run(
        tenant,
        goal="Review the exact case without executing live actions.",
        actor="analyst@example.com",
        case_id=None,
        max_steps=3,
    )
    session.commit()

    assert run.status == "denied"
    assert run.reason == "capability_denied:no_matching_exact_action_artifact"
    assert run.disposition["code"] == "denied_no_authorization"
    assert run.disposition["retryable"] is False
    assert run.steps == []
    assert ai.calls == 0
    assert bus.events == []
    durable = session.query(AutonomousAgentRun).filter_by(run_id=run.run_id).one()
    assert durable.status == "denied"
    assert durable.action_digest == run.action_digest


def test_run_flush_failure_raises_and_creates_no_replay_entry(
    monkeypatch,
    session,
    tenant,
):
    ai = RecordingAI()
    bus = RecordingBus()
    agent = AutonomousAgent(session, ai=ai, event_bus=bus)
    monkeypatch.setattr(agent, "_tool_attack_summary", _fail_if_tool_runs)

    def fail_run_flush(db_session, flush_context, instances):
        if any(isinstance(row, AutonomousAgentRun) for row in db_session.new):
            raise RuntimeError("run database unavailable")

    event.listen(session, "before_flush", fail_run_flush)
    try:
        with pytest.raises(AgentPersistenceError):
            agent.run(
                tenant,
                goal="Persist this denied action before returning it.",
                actor="analyst@example.com",
                case_id=None,
                max_steps=3,
            )
    finally:
        event.remove(session, "before_flush", fail_run_flush)

    assert agent.list_runs(tenant=tenant) == []
    assert ai.calls == 0
    assert bus.events == []
