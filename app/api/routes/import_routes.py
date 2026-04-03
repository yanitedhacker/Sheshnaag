"""SBOM and VEX import APIs."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.services.import_service import ImportService
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/imports", tags=["Imports"])


class SBOMImportRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    document: Dict[str, Any]
    asset_id: Optional[int] = None
    service_id: Optional[int] = None


class VEXImportRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    document: Dict[str, Any]


@router.post("/sbom")
def import_sbom(
    request: SBOMImportRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Import SBOM data for a writable tenant."""
    auth_service = AuthService(session)
    tenant = auth_service.resolve_private_tenant(token_data=token_data, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    auth_service.assert_tenant_access(tenant, token_data, access="write")
    service = ImportService(session)
    return service.import_sbom(
        tenant,
        document=request.document,
        asset_id=request.asset_id,
        service_id=request.service_id,
    )


@router.post("/vex")
def import_vex(
    request: VEXImportRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Import VEX statements for a writable tenant."""
    auth_service = AuthService(session)
    tenant = auth_service.resolve_private_tenant(token_data=token_data, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    auth_service.assert_tenant_access(tenant, token_data, access="write")
    service = ImportService(session)
    return service.import_vex(tenant, document=request.document)
