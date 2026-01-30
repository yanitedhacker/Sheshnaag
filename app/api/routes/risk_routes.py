"""Risk scoring API endpoints."""

from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_sync_session
from app.services.risk_aggregator import RiskAggregator

router = APIRouter(prefix="/api/risk", tags=["Risk Scoring"])


class RiskScoreResponse(BaseModel):
    """Risk score response model."""
    cve_id: str
    overall_risk_score: float
    risk_level: str
    exploit_probability: float
    priority_rank: Optional[int]
    explanation: Optional[str]
    top_features: Optional[List[dict]]


class TopPrioritiesResponse(BaseModel):
    """Top priorities response."""
    priorities: List[dict]
    count: int


class RiskSummaryResponse(BaseModel):
    """Risk summary response."""
    total_cves_scored: int
    risk_level_distribution: dict
    average_risk_score: float
    average_exploit_probability: float
    recent_critical_cves: int
    cves_with_exploits: int
    last_updated: str


@router.get("/priorities")
def get_top_priorities(
    limit: int = Query(10, ge=1, le=100, description="Number of results"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level (CRITICAL, HIGH, MEDIUM, LOW)"),
    asset_id: Optional[int] = Query(None, description="Filter by asset ID"),
    session: Session = Depends(get_sync_session)
):
    """
    Get top priority CVEs for patching.
    
    Returns CVEs sorted by overall risk score, with optional filtering
    by risk level or specific asset.
    """
    aggregator = RiskAggregator(session)
    priorities = aggregator.get_top_priorities(
        limit=limit,
        risk_level=risk_level,
        asset_id=asset_id
    )
    
    return {
        "priorities": priorities,
        "count": len(priorities)
    }


@router.get("/summary")
def get_risk_summary(
    session: Session = Depends(get_sync_session)
):
    """
    Get overall risk summary statistics.
    
    Includes risk level distribution, average scores, and critical CVE counts.
    """
    aggregator = RiskAggregator(session)
    return aggregator.get_risk_summary()


@router.get("/heatmap")
def get_risk_heatmap(
    session: Session = Depends(get_sync_session)
):
    """
    Get data for risk heatmap visualization.
    
    Returns CVE counts bucketed by CVSS severity and exploit availability.
    """
    aggregator = RiskAggregator(session)
    return aggregator.get_risk_heatmap_data()


@router.post("/calculate")
def calculate_risks(
    limit: Optional[int] = Query(None, description="Max CVEs to process"),
    background_tasks: BackgroundTasks = None,
    session: Session = Depends(get_sync_session)
):
    """
    Trigger risk score calculation for CVEs.
    
    Calculates risk scores for CVEs that don't have recent scores.
    Can run in background for large datasets.
    """
    aggregator = RiskAggregator(session)
    
    # For now, run synchronously (could be made async with Celery)
    results = aggregator.calculate_all_risks(limit=limit)
    
    return {
        "status": "completed",
        "results": results
    }


@router.get("/cve/{cve_id}")
def get_cve_risk_score(
    cve_id: str,
    session: Session = Depends(get_sync_session)
):
    """
    Get risk score for a specific CVE.
    
    - **cve_id**: CVE identifier (e.g., CVE-2024-1234)
    """
    from app.models.cve import CVE
    from app.models.risk_score import RiskScore
    from sqlalchemy import desc
    
    cve = session.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    # Get latest risk score
    risk_score = session.query(RiskScore).filter(
        RiskScore.cve_id == cve.id
    ).order_by(desc(RiskScore.created_at)).first()
    
    if not risk_score:
        # Calculate on-demand
        aggregator = RiskAggregator(session)
        risk_score = aggregator.calculate_cve_risk(cve)
        session.commit()
    
    return {
        "cve_id": cve.cve_id,
        "overall_score": risk_score.overall_score,
        "risk_level": risk_score.risk_level,
        "exploit_probability": risk_score.exploit_probability,
        "impact_score": risk_score.impact_score,
        "exposure_score": risk_score.exposure_score,
        "temporal_score": risk_score.temporal_score,
        "confidence_score": risk_score.confidence_score,
        "confidence_band": {
            "lower": risk_score.confidence_band_lower,
            "upper": risk_score.confidence_band_upper
        },
        "priority_rank": risk_score.priority_rank,
        "top_features": risk_score.top_features,
        "explanation": risk_score.explanation,
        "model_version": risk_score.model_version,
        "calculated_at": risk_score.created_at.isoformat()
    }


@router.get("/timeline/{cve_id}")
def get_risk_timeline(
    cve_id: str,
    limit: int = Query(30, ge=1, le=100, description="Number of history records"),
    session: Session = Depends(get_sync_session)
):
    """
    Get risk score history for a CVE.
    
    Useful for tracking how risk has changed over time.
    """
    from app.models.cve import CVE
    from app.models.risk_score import RiskHistory
    from sqlalchemy import desc
    
    cve = session.query(CVE).filter(CVE.cve_id == cve_id.upper()).first()
    
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    
    history = session.query(RiskHistory).filter(
        RiskHistory.cve_id == cve.id
    ).order_by(desc(RiskHistory.recorded_at)).limit(limit).all()
    
    return {
        "cve_id": cve.cve_id,
        "history": [
            {
                "overall_score": h.overall_score,
                "risk_level": h.risk_level,
                "exploit_probability": h.exploit_probability,
                "change_reason": h.change_reason,
                "recorded_at": h.recorded_at.isoformat()
            }
            for h in history
        ]
    }
