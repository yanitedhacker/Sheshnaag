"""Tests for WS1-T5: Source freshness and update history."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult
from app.ingestion.sync_state import record_sync_run
from app.models.ops import FeedSyncRun
from app.models.sheshnaag import SourceFeed


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


# ------------------------------------------------------------------
# FeedSyncRun model creation
# ------------------------------------------------------------------

@pytest.mark.unit
def test_feed_sync_run_creation():
    session = _make_session()
    now = utc_now()
    run = FeedSyncRun(
        source="NVD",
        status="success",
        started_at=now - timedelta(seconds=30),
        ended_at=now,
        items_fetched=150,
        items_new=10,
        items_updated=5,
    )
    session.add(run)
    session.commit()

    fetched = session.query(FeedSyncRun).filter(FeedSyncRun.source == "NVD").first()
    assert fetched is not None
    assert fetched.status == "success"
    assert fetched.items_fetched == 150
    assert fetched.items_new == 10
    assert fetched.items_updated == 5
    assert fetched.error_summary is None
    assert fetched.created_at is not None


@pytest.mark.unit
def test_feed_sync_run_failed_with_error_summary():
    session = _make_session()
    now = utc_now()
    run = FeedSyncRun(
        source="KEV",
        status="failed",
        started_at=now,
        ended_at=now,
        error_summary="Connection timeout",
    )
    session.add(run)
    session.commit()

    fetched = session.query(FeedSyncRun).filter(FeedSyncRun.source == "KEV").first()
    assert fetched.status == "failed"
    assert fetched.error_summary == "Connection timeout"
    assert fetched.items_fetched == 0


# ------------------------------------------------------------------
# record_sync_run from ConnectorResult
# ------------------------------------------------------------------

@pytest.mark.unit
def test_record_sync_run_from_connector_result():
    session = _make_session()
    now = utc_now()
    cr = ConnectorResult(
        source="NVD",
        items_fetched=42,
        items_new=8,
        items_updated=3,
        started_at=now.isoformat(),
        completed_at=now.isoformat(),
    )

    run = record_sync_run(session, cr, status="success", raw_payload_hash="abc123")
    session.commit()

    assert run.id is not None
    assert run.source == "NVD"
    assert run.status == "success"
    assert run.items_fetched == 42
    assert run.items_new == 8
    assert run.items_updated == 3
    assert run.raw_payload_hash == "abc123"
    assert run.started_at is not None
    assert run.ended_at is not None


@pytest.mark.unit
def test_record_sync_run_with_missing_timestamps():
    session = _make_session()
    cr = ConnectorResult(source="EPSS", items_fetched=100)

    run = record_sync_run(session, cr, status="success")
    session.commit()

    assert run.started_at is not None
    assert run.ended_at is not None


@pytest.mark.unit
def test_record_sync_run_failed():
    session = _make_session()
    cr = ConnectorResult(source="OSV", started_at=utc_now().isoformat())

    run = record_sync_run(session, cr, status="failed", error_summary="HTTP 503")
    session.commit()

    assert run.status == "failed"
    assert run.error_summary == "HTTP 503"


# ------------------------------------------------------------------
# Stale status detection
# ------------------------------------------------------------------

def _is_stale(last_synced_at: datetime | None, threshold_seconds: int) -> bool:
    """Reproduce the staleness logic used by the feed-status route."""
    if last_synced_at is None:
        return True
    now = utc_now().replace(tzinfo=None)
    synced = last_synced_at.replace(tzinfo=None) if last_synced_at.tzinfo else last_synced_at
    return (now - synced).total_seconds() > threshold_seconds


@pytest.mark.unit
def test_stale_detection_fresh_feed():
    session = _make_session()
    feed = SourceFeed(
        feed_key="nvd",
        display_name="NVD",
        status="active",
        freshness_seconds=21600,
        last_synced_at=utc_now() - timedelta(seconds=100),
    )
    session.add(feed)
    session.commit()

    assert _is_stale(feed.last_synced_at, feed.freshness_seconds) is False


@pytest.mark.unit
def test_stale_detection_stale_feed():
    session = _make_session()
    feed = SourceFeed(
        feed_key="kev",
        display_name="CISA KEV",
        status="active",
        freshness_seconds=3600,
        last_synced_at=utc_now() - timedelta(hours=2),
    )
    session.add(feed)
    session.commit()

    assert _is_stale(feed.last_synced_at, feed.freshness_seconds) is True


@pytest.mark.unit
def test_stale_detection_never_synced():
    session = _make_session()
    feed = SourceFeed(
        feed_key="osv",
        display_name="OSV",
        status="planned",
        freshness_seconds=21600,
    )
    session.add(feed)
    session.commit()

    assert feed.last_synced_at is None
    assert _is_stale(feed.last_synced_at, feed.freshness_seconds) is True
