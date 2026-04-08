"""Sheshnaag intel APIs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.core.time import utc_now
from app.models.ops import FeedSyncRun
from app.models.sheshnaag import SourceFeed
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/intel", tags=["Sheshnaag Intel"])

_DEFAULT_STALE_SECONDS = 21600  # 6 hours


@router.get("/overview")
def get_intel_overview(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Return source health and candidate-readiness overview."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).get_intel_overview(tenant)


@router.get("/feed-history")
def get_feed_history(
    source: Optional[str] = Query(None, description="Filter by source key"),
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_sync_session),
) -> List[Dict[str, Any]]:
    """Return recent FeedSyncRun rows, optionally filtered by source."""
    q = session.query(FeedSyncRun).order_by(desc(FeedSyncRun.id))
    if source:
        q = q.filter(FeedSyncRun.source == source.upper())
    runs = q.limit(limit).all()
    return [
        {
            "id": r.id,
            "source": r.source,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "items_fetched": r.items_fetched,
            "items_new": r.items_new,
            "items_updated": r.items_updated,
            "error_summary": r.error_summary,
            "raw_payload_hash": r.raw_payload_hash,
        }
        for r in runs
    ]


@router.get("/feed-status")
def get_feed_status(
    session: Session = Depends(get_sync_session),
) -> List[Dict[str, Any]]:
    """Per-feed status with last run info and stale threshold check."""
    feeds = session.query(SourceFeed).order_by(SourceFeed.display_name.asc()).all()

    latest_run_subq = (
        session.query(
            FeedSyncRun.source,
            func.max(FeedSyncRun.id).label("max_id"),
        )
        .group_by(FeedSyncRun.source)
        .subquery()
    )
    latest_runs_q = (
        session.query(FeedSyncRun)
        .join(latest_run_subq, FeedSyncRun.id == latest_run_subq.c.max_id)
        .all()
    )
    run_by_source: Dict[str, FeedSyncRun] = {r.source.lower(): r for r in latest_runs_q}

    now = utc_now()
    result: List[Dict[str, Any]] = []
    for feed in feeds:
        threshold = feed.freshness_seconds or _DEFAULT_STALE_SECONDS
        last_run = run_by_source.get(feed.feed_key)
        is_stale = True
        if feed.last_synced_at:
            age = (now - feed.last_synced_at).total_seconds()
            is_stale = age > threshold

        entry: Dict[str, Any] = {
            "feed_key": feed.feed_key,
            "display_name": feed.display_name,
            "status": feed.status,
            "last_synced_at": feed.last_synced_at.isoformat() if feed.last_synced_at else None,
            "freshness_seconds": threshold,
            "is_stale": is_stale,
            "last_run": None,
        }
        if last_run:
            entry["last_run"] = {
                "id": last_run.id,
                "status": last_run.status,
                "started_at": last_run.started_at.isoformat() if last_run.started_at else None,
                "ended_at": last_run.ended_at.isoformat() if last_run.ended_at else None,
                "items_fetched": last_run.items_fetched,
                "items_new": last_run.items_new,
                "items_updated": last_run.items_updated,
                "error_summary": last_run.error_summary,
            }
        result.append(entry)
    return result
