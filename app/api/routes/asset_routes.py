"""Asset management API endpoints."""

from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.core.tenancy import resolve_tenant
from app.services.auth_service import AuthService
from app.services.asset_service import AssetService

router = APIRouter(prefix="/api/assets", tags=["Assets"])


class SoftwareItem(BaseModel):
    """Software item model."""
    vendor: str
    product: str
    version: Optional[str] = None


class AssetCreate(BaseModel):
    """Asset creation model."""
    tenant_id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=200)
    asset_type: Optional[str] = Field(None, description="server, application, network_device, etc.")
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    environment: Optional[str] = Field(None, description="production, staging, development")
    criticality: str = Field("medium", description="critical, high, medium, low")
    business_criticality: Optional[str] = Field(None, description="business criticality override")
    is_crown_jewel: bool = False
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
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """
    Create a new asset.
    
    Assets represent servers, applications, or other infrastructure
    that can be scanned for vulnerabilities.
    """
    auth_service = AuthService(session)
    tenant_id = asset_data.tenant_id
    if tenant_id is None and token_data and token_data.memberships:
        tenant = auth_service.resolve_private_tenant(token_data=token_data)
        tenant_id = tenant.id
    elif tenant_id is not None:
        tenant = auth_service.resolve_private_tenant(token_data=token_data, tenant_id=tenant_id)
    else:
        tenant = None

    if tenant is not None:
        auth_service.assert_tenant_access(tenant, token_data, access="write")
    service = AssetService(session)
    
    # Convert software items to dict format
    software_list = [
        {"vendor": s.vendor, "product": s.product, "version": s.version}
        for s in asset_data.installed_software
    ]
    
    asset = service.create_asset({
        **asset_data.model_dump(exclude={"installed_software"}),
        "tenant_id": tenant_id,
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
    tenant_slug: Optional[str] = Query(None, description="Tenant slug. Defaults to demo-public."),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_sync_session)
):
    """List all assets with optional filters."""
    tenant = resolve_tenant(session, tenant_slug=tenant_slug, default_to_demo=True)
    service = AssetService(session)
    return service.list_assets(
        tenant_id=tenant.id,
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
    tenant_slug: Optional[str] = Query(None, description="Tenant slug. Defaults to demo-public."),
    session: Session = Depends(get_sync_session)
):
    """
    Get organization-wide vulnerability risk summary.
    
    Includes asset counts, vulnerability distribution, and most vulnerable assets.
    """
    tenant = resolve_tenant(session, tenant_slug=tenant_slug, default_to_demo=True)
    service = AssetService(session)
    return service.get_organization_risk_summary(tenant_id=tenant.id)
