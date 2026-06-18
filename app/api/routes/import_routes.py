"""SBOM and VEX import APIs."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.services.auth_service import AuthService
from app.services.import_service import ImportService

router = APIRouter(prefix="/api/imports", tags=["Imports"])


class SBOMImportRequest(BaseModel):
    tenant_id: int | None = None
    tenant_slug: str | None = None
    document: dict[str, Any]
    asset_id: int | None = None
    service_id: int | None = None


class VEXImportRequest(BaseModel):
    tenant_id: int | None = None
    tenant_slug: str | None = None
    document: dict[str, Any]


@router.post("/sbom")
def import_sbom(
    request: SBOMImportRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData | None = Depends(verify_token_optional),
):
    """Import SBOM data for a writable tenant."""
    auth_service = AuthService(session)
    tenant = auth_service.resolve_private_tenant(
        token_data=token_data, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug
    )
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
    token_data: TokenData | None = Depends(verify_token_optional),
):
    """Import VEX statements for a writable tenant."""
    auth_service = AuthService(session)
    tenant = auth_service.resolve_private_tenant(
        token_data=token_data, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug
    )
    auth_service.assert_tenant_access(tenant, token_data, access="write")
    service = ImportService(session)
    return service.import_vex(tenant, document=request.document)
