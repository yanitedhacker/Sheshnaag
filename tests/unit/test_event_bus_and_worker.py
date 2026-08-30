"""Unit coverage for the Phase 1 event bus and sandbox worker."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.event_bus import EventBus
from app.models.sheshnaag import EvidenceArtifact, LabRecipe, LabRun, RecipeRevision, RunEvent
from app.models.v2 import Tenant
from app.workers import sandbox_worker
from app.workers.routing import SANDBOX_CONSUMER_GROUP, WorkerCapabilityMismatch


ROOT = Path(__file__).resolve().parents[2]


def test_worker_healthcheck_requires_redis_and_database(monkeypatch):
    calls: list[str] = []

    class FakeRedis:
        def ping(self):
            calls.append("redis")
            return True

        def close(self):
            calls.append("redis_close")

    class FakeSession:
        def execute(self, statement):
            assert str(statement) == "SELECT 1"
            calls.append("database")

        def close(self):
            calls.append("database_close")

    monkeypatch.setattr(sandbox_worker.redis, "from_url", lambda *_args, **_kwargs: FakeRedis())
    monkeypatch.setattr(sandbox_worker, "SessionLocal", FakeSession)

    assert sandbox_worker.check_worker_dependencies() is True
    assert calls == ["redis", "database", "database_close", "redis_close"]


def test_worker_healthcheck_cli_fails_closed(monkeypatch):
    monkeypatch.setattr(sandbox_worker, "check_worker_dependencies", lambda: False)
    monkeypatch.setattr(
        sandbox_worker,
        "run_forever",
        lambda: (_ for _ in ()).throw(AssertionError("worker loop must not start")),
    )

    assert sandbox_worker.main(["--healthcheck"]) == 1


def test_compose_worker_overrides_api_http_healthcheck():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    worker = compose.split("  worker:\n", 1)[1].split("  frontend:\n", 1)[0]

    assert "healthcheck:" in worker
    assert (
        '["CMD", "python", "-m", "app.workers.sandbox_worker", "--healthcheck"]'
        in worker
    )
    assert (
        "SHESHNAAG_WORKER_CAPABILITIES: ${SHESHNAAG_WORKER_CAPABILITIES:-docker}"
        in worker
    )


def test_sandbox_worker_treats_redis_read_timeout_as_empty_poll():
    class TimedOutClient:
        def xreadgroup(self, group, consumer, streams, *, block, count):
            assert group == SANDBOX_CONSUMER_GROUP
            assert consumer == "sandbox-worker-1"
            assert streams == {"sheshnaag:sandbox:work:standard": ">"}
            assert block == 1000
            assert count == 1
            raise sandbox_worker.redis.exceptions.TimeoutError(
                "idle blocking read timed out"
            )

    assert sandbox_worker._read_work_rows(
        TimedOutClient(),
        group=SANDBOX_CONSUMER_GROUP,
        consumer="sandbox-worker-1",
        streams={"sheshnaag:sandbox:work:standard": ">"},
    ) == []


def test_sandbox_worker_rejects_incompatible_job_before_database_access(monkeypatch):
    monkeypatch.setattr(
        sandbox_worker,
        "SessionLocal",
        lambda: (_ for _ in ()).throw(AssertionError("database must not be opened")),
    )
    message = {
        "run_id": 10,
        "tenant_id": 2,
        "routing_version": 1,
        "required_capabilities": [
            "kvm",
            "libvirt",
            "linux",
            "pcap",
            "secure-mode",
            "zeek",
        ],
    }

    with pytest.raises(WorkerCapabilityMismatch):
        sandbox_worker.process_sandbox_work(message, worker_capabilities={"docker"})


def test_event_bus_uses_in_memory_fallback_when_redis_unavailable():
    bus = EventBus(redis_url="redis://127.0.0.1:1/0")
    entry_id = bus.publish("test:stream", {"type": "run_queued", "run_id": 42})

    event = next(bus.subscribe("test:stream", last_id="0-0", block_ms=1))

    assert event["id"] == entry_id
    assert event["type"] == "run_queued"
    assert event["run_id"] == 42


def test_sandbox_worker_marks_run_completed_and_publishes_events(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    tenant = Tenant(slug="worker-private", name="Worker Private")
    session.add(tenant)
    session.flush()
    recipe = LabRecipe(
        tenant_id=tenant.id,
        candidate_id=None,
        template_id=None,
        name="Worker recipe",
        objective="Worker test",
        provider="docker_kali",
        created_by="Worker",
        current_revision_number=1,
    )
    session.add(recipe)
    session.flush()
    revision = RecipeRevision(
        recipe_id=recipe.id, revision_number=1, approval_state="approved", content={}
    )
    session.add(revision)
    session.flush()
    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=revision.id,
        provider="docker_kali",
        launch_mode="execute",
        state="queued",
        manifest={"analysis_mode": "cve_validation", "specimen_ids": []},
    )
    session.add(run)
    session.commit()
    run_id = run.id
    tenant_id = tenant.id
    session.close()

    class FakeExecutionService:
        def __init__(self, session):
            self.session = session

        def execute_queued_run(self, tenant, *, run_id, actor):
            assert actor == "analyst"
            stored = self.session.get(LabRun, run_id)
            assert stored.state == "queued"
            stored.state = "completed"
            return {"state": "completed", "evidence_count": 1}

    published = []

    class FakeBus:
        def publish(self, stream, event):
            published.append((stream, event))
            return "1-0"

    monkeypatch.setattr(sandbox_worker, "SessionLocal", TestingSession)
    monkeypatch.setattr(sandbox_worker, "SheshnaagService", FakeExecutionService)

    result = sandbox_worker.process_sandbox_work(
        {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "actor": "analyst",
            "correlation_id": "abc",
            "routing_version": 1,
            "required_capabilities": ["docker"],
        },
        bus=FakeBus(),
        worker_capabilities={"docker"},
    )

    verify = TestingSession()
    stored = verify.get(LabRun, run_id)
    event_types = [
        row.event_type for row in verify.query(RunEvent).filter(RunEvent.run_id == run_id).all()
    ]
    verify.close()

    assert result["status"] == "completed"
    assert result["result"]["evidence_count"] == 1
    assert stored.state == "completed"
    assert {"run_started", "run_completed"}.issubset(set(event_types))
    assert [event["type"] for _, event in published] == ["run_started", "run_completed"]


def test_sandbox_worker_completed_replay_is_idempotent(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    tenant = Tenant(slug="worker-replay", name="Worker Replay")
    session.add(tenant)
    session.flush()
    recipe = LabRecipe(
        tenant_id=tenant.id,
        name="Replay recipe",
        provider="docker_kali",
        current_revision_number=1,
    )
    session.add(recipe)
    session.flush()
    revision = RecipeRevision(
        recipe_id=recipe.id,
        revision_number=1,
        approval_state="approved",
        content={},
    )
    session.add(revision)
    session.flush()
    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=revision.id,
        provider="docker_kali",
        launch_mode="execute",
        state="completed",
        manifest={
            "worker_execution": {
                "evidence_count": 1,
                "live_evidence_count": 1,
                "cleanup_state": "destroyed",
            }
        },
    )
    session.add(run)
    session.flush()
    session.add(
        EvidenceArtifact(
            run_id=run.id,
            artifact_kind="service_logs",
            title="Replay evidence",
            sha256="a" * 64,
            payload={"collection_state": "live"},
        )
    )
    session.commit()
    run_id = run.id
    tenant_id = tenant.id
    session.close()

    class NoPublishBus:
        def publish(self, stream, event):
            raise AssertionError("idempotent replay must not publish lifecycle events")

    monkeypatch.setattr(sandbox_worker, "SessionLocal", TestingSession)

    result = sandbox_worker.process_sandbox_work(
        {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "routing_version": 1,
            "required_capabilities": ["docker"],
        },
        bus=NoPublishBus(),
        worker_capabilities={"docker"},
    )

    assert result == {
        "run_id": run_id,
        "status": "completed",
        "result": {
            "state": "completed",
            "evidence_count": 1,
            "live_evidence_count": 1,
            "cleanup_state": "destroyed",
        },
    }


def test_sandbox_worker_marks_run_errored_when_preflight_fails(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    tenant = Tenant(slug="worker-preflight", name="Worker Preflight")
    session.add(tenant)
    session.flush()
    recipe = LabRecipe(
        tenant_id=tenant.id, name="Worker recipe", provider="docker_kali", current_revision_number=1
    )
    session.add(recipe)
    session.flush()
    revision = RecipeRevision(
        recipe_id=recipe.id, revision_number=1, approval_state="approved", content={}
    )
    session.add(revision)
    session.flush()
    run = LabRun(
        tenant_id=tenant.id,
        recipe_revision_id=revision.id,
        provider="lima",
        launch_mode="execute",
        state="queued",
        manifest={"analysis_mode": "url_analysis", "specimen_ids": [99]},
    )
    session.add(run)
    session.commit()
    run_id = run.id
    tenant_id = tenant.id
    session.close()

    class FakeService:
        def __init__(self, session):
            self.session = session

        def enforce_run_execution_preflight(self, tenant, *, run, actor):
            raise ValueError("capability_required:dynamic_detonation")

        def materialize_run_outputs(self, tenant, *, run):  # pragma: no cover
            raise AssertionError("materialization must not run")

    published = []

    class FakeBus:
        def publish(self, stream, event):
            published.append((stream, event))
            return "1-0"

    monkeypatch.setattr(sandbox_worker, "SessionLocal", TestingSession)
    monkeypatch.setattr(sandbox_worker, "MalwareLabService", FakeService)

    try:
        sandbox_worker.process_sandbox_work(
            {
                "run_id": run_id,
                "tenant_id": tenant_id,
                "actor": "analyst",
                "correlation_id": "abc",
                "routing_version": 1,
                "required_capabilities": ["docker"],
            },
            bus=FakeBus(),
            worker_capabilities={"docker"},
        )
    except ValueError:
        pass

    verify = TestingSession()
    stored = verify.get(LabRun, run_id)
    event_types = [
        row.event_type for row in verify.query(RunEvent).filter(RunEvent.run_id == run_id).all()
    ]
    verify.close()

    assert stored.state == "errored"
    assert "run_failed" in event_types
    assert [event["type"] for _, event in published] == ["run_started", "run_failed"]
