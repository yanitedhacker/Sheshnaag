"""CVE API endpoints."""

import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.services.cve_service import CVEService

router = APIRouter(prefix="/api/cves", tags=["CVEs"])

# CVE ID format: CVE-YYYY-NNNNN (year followed by at least 4 digits)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CVEResponse(BaseModel):
    """CVE response model."""

    id: int
    cve_id: str
    description: str | None
    published_date: str | None
    cvss_v3_score: float | None
    attack_vector: str | None
    exploit_available: bool
    risk: dict | None = None

    class Config:
        from_attributes = True


class CVESearchResponse(BaseModel):
    """CVE search response."""

    results: list[dict]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("/{cve_id}")
def get_cve(cve_id: str, session: Session = Depends(get_sync_session)):
    """
    Get detailed CVE information by CVE ID.

    - **cve_id**: CVE identifier (e.g., CVE-2024-1234)
    """
    # Validate CVE ID format
    if not CVE_ID_PATTERN.match(cve_id):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNNN",
        )

    service = CVEService(session)
    cve = service.get_cve_by_id(cve_id.upper())

    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    return cve


@router.get("/", response_model=CVESearchResponse)
def search_cves(
    keyword: str | None = Query(None, description="Search keyword"),
    vendor: str | None = Query(None, description="Filter by vendor"),
    product: str | None = Query(None, description="Filter by product"),
    min_cvss: float | None = Query(None, ge=0, le=10, description="Minimum CVSS score"),
    max_cvss: float | None = Query(None, ge=0, le=10, description="Maximum CVSS score"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    has_exploit: bool | None = Query(None, description="Filter by exploit availability"),
    start_date: datetime | None = Query(None, description="Start date filter"),
    end_date: datetime | None = Query(None, description="End date filter"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    session: Session = Depends(get_sync_session),
):
    """
    Search CVEs with various filters.

    Supports keyword search, vendor/product filtering, CVSS range,
    risk level, exploit status, and date range.
    """
    service = CVEService(session)

    return service.search_cves(
        keyword=keyword,
        vendor=vendor,
        product=product,
        min_cvss=min_cvss,
        max_cvss=max_cvss,
        risk_level=risk_level,
        has_exploit=has_exploit,
        start_date=start_date,
        end_date=end_date,
        page=page,
        page_size=page_size,
    )


@router.get("/recent/list")
def get_recent_cves(
    days: int = Query(7, ge=1, le=90, description="Number of days"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    session: Session = Depends(get_sync_session),
):
    """Get CVEs published in the last N days."""
    service = CVEService(session)
    return service.get_recent_cves(days=days, limit=limit)


@router.get("/trending/list")
def get_trending_cves(
    limit: int = Query(10, ge=1, le=50, description="Maximum results"),
    session: Session = Depends(get_sync_session),
):
    """
    Get trending CVEs based on recent activity and risk.

    Considers new exploits, high risk scores, and recent modifications.
    """
    service = CVEService(session)
    return service.get_trending_cves(limit=limit)


@router.get("/statistics/summary")
def get_cve_statistics(session: Session = Depends(get_sync_session)):
    """Get overall CVE statistics."""
    service = CVEService(session)
    return service.get_cve_statistics()
