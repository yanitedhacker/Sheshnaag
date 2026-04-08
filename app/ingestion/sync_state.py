"""Utilities for tracking feed sync state."""

from __future__ import annotations

from datetime import datetime
from app.core.time import utc_now
from typing import Optional

from sqlalchemy.orm import Session

from app.ingestion.connector import ConnectorResult
from app.models.ops import FeedSyncRun, FeedSyncState


def get_or_create_state(session: Session, source: str) -> FeedSyncState:
    state = session.query(FeedSyncState).filter(FeedSyncState.source == source).first()
    if state:
        return state
    state = FeedSyncState(source=source, status="idle")
    session.add(state)
    session.flush()
    return state


def mark_running(session: Session, state: FeedSyncState):
    state.status = "running"
    state.last_run_at = utc_now()
    state.last_error = None
    session.add(state)


def mark_success(session: Session, state: FeedSyncState, cursor: Optional[str] = None):
    now = utc_now()
    state.status = "success"
    state.last_success_at = now
    state.updated_at = now
    if cursor:
        state.cursor = cursor
    session.add(state)


def mark_failed(session: Session, state: FeedSyncState, error: str):
    state.status = "failed"
    state.last_error = error
    session.add(state)


def record_sync_run(
    session: Session,
    result: ConnectorResult,
    *,
    status: str = "success",
    error_summary: Optional[str] = None,
    raw_payload_hash: Optional[str] = None,
) -> FeedSyncRun:
    """Persist a FeedSyncRun row from a ConnectorResult."""
    started = None
    if result.started_at:
        try:
            started = datetime.fromisoformat(result.started_at)
        except (ValueError, TypeError):
            started = None

    ended = None
    if result.completed_at:
        try:
            ended = datetime.fromisoformat(result.completed_at)
        except (ValueError, TypeError):
            ended = None

    if not started:
        started = utc_now()
    if not ended:
        ended = utc_now()

    run = FeedSyncRun(
        source=result.source,
        status=status,
        started_at=started,
        ended_at=ended,
        items_fetched=result.items_fetched,
        items_new=result.items_new,
        items_updated=result.items_updated,
        error_summary=error_summary,
        raw_payload_hash=raw_payload_hash,
    )
    session.add(run)
    session.flush()
    return run
