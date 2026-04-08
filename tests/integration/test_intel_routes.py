"""WS1-T9 integration tests for live intel routes.

Self-contained tests that use an in-memory SQLite database and a
test-specific FastAPI app so no external services are required.
"""

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import DateTime, create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.intel_routes import router as intel_router
from app.core.database import Base, get_sync_session
from app.models.ops import FeedSyncRun, FeedSyncState
from app.models.sheshnaag import SourceFeed
from app.services.demo_seed_service import DemoSeedService

pytestmark = pytest.mark.integration

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _fix_naive_datetimes(target, context):
    """After loading a row from SQLite, upgrade naive datetimes to UTC."""
    for col in target.__class__.__table__.columns:
        if isinstance(col.type, DateTime):
            val = target.__dict__.get(col.key)
            if isinstance(val, datetime) and val.tzinfo is None:
                target.__dict__[col.key] = val.replace(tzinfo=timezone.utc)


for _cls in (SourceFeed, FeedSyncRun, FeedSyncState):
    event.listen(_cls, "load", _fix_naive_datetimes)


def override_get_sync_session():
    session = TestingSession()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


test_app = FastAPI()
test_app.include_router(intel_router)
test_app.dependency_overrides[get_sync_session] = override_get_sync_session

client = TestClient(test_app)


@pytest.fixture(scope="module", autouse=True)
def seed_database():
    """Create tables and seed demo data once for the whole module."""
    Base.metadata.create_all(bind=engine)
    session = TestingSession()
    try:
        DemoSeedService(session).seed()
        session.commit()
    finally:
        session.close()
    yield
    Base.metadata.drop_all(bind=engine)


class TestIntelOverview:
    def test_returns_200(self):
        r = client.get("/api/intel/overview")
        assert r.status_code == 200

    def test_response_has_sources_array(self):
        data = client.get("/api/intel/overview").json()
        assert isinstance(data["sources"], list)
        assert len(data["sources"]) > 0

    def test_response_has_summary(self):
        data = client.get("/api/intel/overview").json()
        assert "summary" in data
        assert "candidate_count" in data["summary"]

    def test_response_has_mission(self):
        data = client.get("/api/intel/overview").json()
        assert "mission" in data
        assert data["mission"]["headline"].startswith("Live CVE intelligence")

    def test_sources_have_freshness_fields(self):
        data = client.get("/api/intel/overview").json()
        for src in data["sources"]:
            assert "freshness_seconds" in src
            assert "last_synced_at" in src
            assert "feed_key" in src
            assert "status" in src
            assert "is_stale" in src
            assert "last_error" in src

    def test_sources_include_expected_statuses(self):
        data = client.get("/api/intel/overview").json()
        statuses = {s["status"] for s in data["sources"]}
        assert "active" in statuses or "planned" in statuses

    def test_active_feeds_present(self):
        data = client.get("/api/intel/overview").json()
        statuses = {s["status"] for s in data["sources"]}
        assert "active" in statuses, "Expected at least one active feed"
        assert statuses <= {"active", "planned", "deprecated"}, f"Unexpected statuses: {statuses}"


class TestFeedStatus:
    def test_returns_200(self):
        r = client.get("/api/intel/feed-status")
        assert r.status_code == 200

    def test_returns_list(self):
        data = client.get("/api/intel/feed-status").json()
        assert isinstance(data, list)

    def test_entries_have_is_stale_field(self):
        data = client.get("/api/intel/feed-status").json()
        assert len(data) > 0
        for entry in data:
            assert "is_stale" in entry
            assert isinstance(entry["is_stale"], bool)

    def test_entries_have_freshness_fields(self):
        data = client.get("/api/intel/feed-status").json()
        for entry in data:
            assert "feed_key" in entry
            assert "display_name" in entry
            assert "status" in entry
            assert "freshness_seconds" in entry
            assert "last_synced_at" in entry

    def test_entries_have_last_run_key(self):
        data = client.get("/api/intel/feed-status").json()
        for entry in data:
            assert "last_run" in entry


class TestFeedHistory:
    def test_returns_200(self):
        r = client.get("/api/intel/feed-history")
        assert r.status_code == 200

    def test_returns_list(self):
        data = client.get("/api/intel/feed-history").json()
        assert isinstance(data, list)

    def test_with_source_filter(self):
        r = client.get("/api/intel/feed-history", params={"source": "nvd"})
        assert r.status_code == 200
        for item in r.json():
            assert item["source"].lower() == "nvd"

    def test_limit_parameter(self):
        r = client.get("/api/intel/feed-history", params={"limit": 5})
        assert r.status_code == 200
        assert len(r.json()) <= 5

    def test_history_after_seeded_run(self):
        """Seed a FeedSyncRun and confirm it appears in history."""
        from app.core.time import utc_now

        session = TestingSession()
        try:
            run = FeedSyncRun(
                source="NVD",
                status="success",
                started_at=utc_now(),
                ended_at=utc_now(),
                items_fetched=42,
                items_new=10,
                items_updated=5,
            )
            session.add(run)
            session.commit()
        finally:
            session.close()

        data = client.get("/api/intel/feed-history", params={"source": "nvd"}).json()
        assert any(item["source"] == "NVD" and item["items_fetched"] == 42 for item in data)


class TestDuplicateCollapsing:
    def test_overview_twice_no_duplicate_source_feeds(self):
        """Calling overview twice should not duplicate SourceFeed rows."""
        client.get("/api/intel/overview")
        client.get("/api/intel/overview")

        session = TestingSession()
        try:
            feed_keys = [f.feed_key for f in session.query(SourceFeed).all()]
            assert len(feed_keys) == len(set(feed_keys)), (
                f"Duplicate feed keys detected: {feed_keys}"
            )
        finally:
            session.close()
