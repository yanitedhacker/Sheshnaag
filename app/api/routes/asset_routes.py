"""Asset management API endpoints."""

from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_sync_session
from app.services.asset_service import AssetService

router = APIRouter(prefix="/api/assets", tags=["Assets"])


class SoftwareItem(BaseModel):
    """Software item model."""
    vendor: str
    product: str
    version: Optional[str] = None


class AssetCreate(BaseModel):
    """Asset creation model."""
    name: str = Field(..., min_length=1, max_length=200)
    asset_type: Optional[str] = Field(None, description="server, application, network_device, etc.")
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = Field(None, description="production, staging, development")
    criticality: str = Field("medium", description="critical, high, medium, low")
    installed_software: List[SoftwareItem] = []
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    tags: List[str] = []
    notes: Optional[str] = None


class AssetResponse(BaseModel):
    """Asset response model."""
    id: int
    name: str
    asset_type: Optional[str]
    hostname: Optional[str]
    environment: Optional[str]
    criticality: str
    open_vulnerabilities: int = 0
    
    class Config:
        from_attributes = True


class VulnerabilityStatusUpdate(BaseModel):
    """Vulnerability status update model."""
    status: str = Field(..., description="open, in_progress, patched, accepted_risk, false_positive")
    notes: Optional[str] = None


@router.post("/")
def create_asset(
    asset_data: AssetCreate,
    session: Session = Depends(get_sync_session)
):
    """
    Create a new asset.
    
    Assets represent servers, applications, or other infrastructure
    that can be scanned for vulnerabilities.
    """
    service = AssetService(session)
    
    # Convert software items to dict format
    software_list = [
        {"vendor": s.vendor, "product": s.product, "version": s.version}
        for s in asset_data.installed_software
    ]
    
    asset = service.create_asset({
        **asset_data.model_dump(exclude={"installed_software"}),
        "installed_software": software_list
    })
    session.commit()
    
    return {"id": asset.id, "name": asset.name, "status": "created"}


@router.get("/{asset_id}")
def get_asset(
    asset_id: int,
    session: Session = Depends(get_sync_session)
):
    """Get asset details by ID."""
    service = AssetService(session)
    asset = service.get_asset(asset_id)
    
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return asset


@router.get("/")
def list_assets(
    environment: Optional[str] = Query(None, description="Filter by environment"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_sync_session)
):
    """List all assets with optional filters."""
    service = AssetService(session)
    return service.list_assets(
        environment=environment,
        criticality=criticality,
        page=page,
        page_size=page_size
    )


@router.post("/{asset_id}/scan")
def scan_asset(
    asset_id: int,
    session: Session = Depends(get_sync_session)
):
    """
    Scan an asset for vulnerabilities.
    
    Matches the asset's installed software against known CVEs.
    """
    service = AssetService(session)
    
    # Check asset exists
    asset = service.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    results = service.scan_asset_for_vulnerabilities(asset_id)
    return results


@router.get("/{asset_id}/vulnerabilities")
def get_asset_vulnerabilities(
    asset_id: int,
    status: Optional[str] = Query(None, description="Filter by status"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    session: Session = Depends(get_sync_session)
):
    """Get vulnerabilities for a specific asset."""
    service = AssetService(session)
    
    # Check asset exists
    asset = service.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return service.get_asset_vulnerabilities(
        asset_id=asset_id,
        status=status,
        risk_level=risk_level
    )


@router.patch("/vulnerabilities/{vulnerability_id}")
def update_vulnerability_status(
    vulnerability_id: int,
    update: VulnerabilityStatusUpdate,
    session: Session = Depends(get_sync_session)
):
    """
    Update vulnerability status.
    
    Use this to mark vulnerabilities as patched, accepted risk, etc.
    """
    service = AssetService(session)
    
    result = service.update_vulnerability_status(
        vulnerability_id=vulnerability_id,
        status=update.status,
        notes=update.notes
    )
    
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    
    return result


@router.get("/organization/summary")
def get_organization_summary(
    session: Session = Depends(get_sync_session)
):
    """
    Get organization-wide vulnerability risk summary.
    
    Includes asset counts, vulnerability distribution, and most vulnerable assets.
    """
    service = AssetService(session)
    return service.get_organization_risk_summary()
