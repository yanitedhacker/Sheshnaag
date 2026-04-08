"""Threat feed management API endpoints."""

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_sync_session
from app.core.time import utc_now
from app.core.security import require_scope
from app.ingestion.feed_aggregator import FeedAggregator
from app.models.ops import FeedSyncState

router = APIRouter(prefix="/api/feeds", tags=["Threat Feeds"])


class SyncResponse(BaseModel):
    """Sync operation response."""
    status: str
    message: str
    results: Optional[dict] = None


@router.post("/sync/cves", dependencies=[Depends(require_scope("admin"))])
async def sync_cves(
    days: int = Query(7, ge=1, le=90, description="Number of days to sync"),
    session: Session = Depends(get_sync_session)
):
    """
    Sync CVEs from NVD.
    
    Fetches CVEs modified in the last N days and stores them in the database.
    """
    aggregator = FeedAggregator(session)
    
    try:
        results = await aggregator.sync_recent_cves(days=days)
        return {
            "status": "completed",
            "message": f"Synced {results['new_cves']} new CVEs, updated {results['updated_cves']}",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync/exploits", dependencies=[Depends(require_scope("admin"))])
async def sync_exploits(
    cve_ids: Optional[list] = None,
    session: Session = Depends(get_sync_session)
):
    """
    Sync exploit information.
    
    Fetches exploit data for CVEs without exploit info or specific CVE IDs.
    """
    aggregator = FeedAggregator(session)
    
    try:
        results = await aggregator.sync_exploits_for_cves(cve_ids=cve_ids)
        return {
            "status": "completed",
            "message": f"Found {results['new_exploits']} new exploits",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync/full", dependencies=[Depends(require_scope("admin"))])
async def full_sync(
    days: int = Query(30, ge=1, le=365, description="Number of days to sync"),
    session: Session = Depends(get_sync_session)
):
    """
    Perform full synchronization of all feeds.
    
    Syncs CVEs from NVD and exploit information from ExploitDB.
    """
    aggregator = FeedAggregator(session)
    
    try:
        results = await aggregator.full_sync(days=days)
        return {
            "status": "completed",
            "message": "Full sync completed",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync/incremental", dependencies=[Depends(require_scope("admin"))])
async def incremental_sync(
    days: int = Query(7, ge=1, le=90, description="Lookback window for CVEs"),
    exploit_limit: int = Query(2000, ge=100, le=10000, description="Max exploit records"),
    session: Session = Depends(get_sync_session),
):
    """
    Incremental sync using persisted cursors for NVD and Exploit-DB.
    """
    aggregator = FeedAggregator(session)
    try:
        results = await aggregator.sync_with_state(days=days, exploit_limit=exploit_limit)
        return {
            "status": "completed",
            "message": "Incremental sync completed",
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def get_feed_status(
    session: Session = Depends(get_sync_session)
):
    """
    Get current status of threat feeds.
    
    Shows last sync times and data counts.
    """
    from sqlalchemy import func
    from app.models.cve import CVE
    from app.models.exploit import Exploit
    from datetime import datetime
    
    # Get counts
    total_cves = session.query(func.count(CVE.id)).scalar()
    total_exploits = session.query(func.count(Exploit.id)).scalar()
    
    # Get latest CVE date
    latest_cve = session.query(func.max(CVE.last_modified_date)).scalar()
    
    # Get latest exploit date
    latest_exploit = session.query(func.max(Exploit.created_at)).scalar()
    
    # CVEs by source
    cves_by_source = session.query(
        CVE.source,
        func.count(CVE.id)
    ).group_by(CVE.source).all()
    
    sync_states = session.query(FeedSyncState).all()
    return {
        "total_cves": total_cves,
        "total_exploits": total_exploits,
        "latest_cve_update": latest_cve.isoformat() if latest_cve else None,
        "latest_exploit_update": latest_exploit.isoformat() if latest_exploit else None,
        "cves_by_source": {source: count for source, count in cves_by_source},
        "sync_state": [
            {
                "source": s.source,
                "status": s.status,
                "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
                "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
                "cursor": s.cursor,
                "last_error": s.last_error,
            }
            for s in sync_states
        ],
        "status": "healthy" if total_cves > 0 else "empty",
        "checked_at": utc_now().isoformat()
    }


@router.get("/sources")
def get_feed_sources():
    """Get information about configured threat feed sources."""
    from app.core.config import settings
    
    return {
        "sources": [
            {
                "name": "NVD (National Vulnerability Database)",
                "url": settings.nvd_base_url,
                "api_key_configured": bool(settings.nvd_api_key),
                "description": "Primary source for CVE data including CVSS scores and affected products"
            },
            {
                "name": "Exploit-DB",
                "url": "https://www.exploit-db.com",
                "api_key_configured": False,
                "description": "Public exploit database for proof-of-concept code"
            },
            {
                "name": "MITRE CVE",
                "url": "https://cve.mitre.org",
                "api_key_configured": False,
                "description": "CVE registration authority (referenced through NVD)"
            }
        ],
        "update_interval_hours": settings.feed_update_interval_hours
    }
