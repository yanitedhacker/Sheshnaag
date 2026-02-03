"""Utilities for tracking feed sync state."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.ops import FeedSyncState


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
    state.last_run_at = datetime.utcnow()
    state.last_error = None
    session.add(state)


def mark_success(session: Session, state: FeedSyncState, cursor: Optional[str] = None):
    now = datetime.utcnow()
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
