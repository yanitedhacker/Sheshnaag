"""Unit coverage for the Phase 1 event bus and sandbox worker."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.event_bus import EventBus
from app.models.sheshnaag import LabRecipe, LabRun, RecipeRevision, RunEvent
from app.models.v2 import Tenant
from app.workers import sandbox_worker


def test_event_bus_uses_in_memory_fallback_when_redis_unavailable():
    bus = EventBus(redis_url="redis://127.0.0.1:1/0")
    entry_id = bus.publish("test:stream", {"type": "run_queued", "run_id": 42})

    event = next(bus.subscribe("test:stream", last_id="0-0", block_ms=1))

    assert event["id"] == entry_id
    assert event["type"] == "run_queued"
    assert event["run_id"] == 42


def test_sandbox_worker_marks_run_completed_and_publishes_events(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
    revision = RecipeRevision(recipe_id=recipe.id, revision_number=1, approval_state="approved", content={})
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

    class FakeService:
        def __init__(self, session):
            self.session = session

        def materialize_run_outputs(self, tenant, *, run):
            return {"evidence_count": 0}

    published = []

    class FakeBus:
        def publish(self, stream, event):
            published.append((stream, event))
            return "1-0"

    monkeypatch.setattr(sandbox_worker, "SessionLocal", TestingSession)
    monkeypatch.setattr(sandbox_worker, "MalwareLabService", FakeService)

    result = sandbox_worker.process_sandbox_work(
        {"run_id": run_id, "tenant_id": tenant_id, "actor": "analyst", "correlation_id": "abc"},
        bus=FakeBus(),
    )

    verify = TestingSession()
    stored = verify.get(LabRun, run_id)
    event_types = [row.event_type for row in verify.query(RunEvent).filter(RunEvent.run_id == run_id).all()]
    verify.close()

    assert result["status"] == "completed"
    assert stored.state == "completed"
    assert {"run_started", "run_completed"}.issubset(set(event_types))
    assert [event["type"] for _, event in published] == ["run_started", "run_completed"]


def test_sandbox_worker_marks_run_errored_when_preflight_fails(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    tenant = Tenant(slug="worker-preflight", name="Worker Preflight")
    session.add(tenant)
    session.flush()
    recipe = LabRecipe(tenant_id=tenant.id, name="Worker recipe", provider="docker_kali", current_revision_number=1)
    session.add(recipe)
    session.flush()
    revision = RecipeRevision(recipe_id=recipe.id, revision_number=1, approval_state="approved", content={})
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
            {"run_id": run_id, "tenant_id": tenant_id, "actor": "analyst", "correlation_id": "abc"},
            bus=FakeBus(),
        )
    except ValueError:
        pass

    verify = TestingSession()
    stored = verify.get(LabRun, run_id)
    event_types = [row.event_type for row in verify.query(RunEvent).filter(RunEvent.run_id == run_id).all()]
    verify.close()

    assert stored.state == "errored"
    assert "run_failed" in event_types
    assert [event["type"] for _, event in published] == ["run_started", "run_failed"]
