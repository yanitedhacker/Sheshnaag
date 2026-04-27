"""OSS maintainer assessment APIs."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.services.auth_service import AuthService
from app.services.maintainer_assessment_service import MaintainerAssessmentService

router = APIRouter(prefix="/api/maintainer", tags=["OSS Maintainer"])


class MaintainerAssessmentCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    repository_url: str
    repository_name: Optional[str] = None
    sbom: Dict[str, Any]
    vex: Optional[Dict[str, Any]] = None
    source_refs: list[Dict[str, Any]] = Field(default_factory=list)
    created_by: str
    export_report: bool = False


@router.post("/assessments")
def create_maintainer_assessment(
    request: MaintainerAssessmentCreateRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Create an OSS maintainer security assessment from SBOM/VEX context."""
    auth = AuthService(session)
    tenant = auth.resolve_private_tenant(
        token_data=token_data,
        tenant_id=request.tenant_id,
        tenant_slug=request.tenant_slug,
    )
    auth.assert_tenant_access(tenant, token_data, access="write")
    try:
        return MaintainerAssessmentService(session).create_assessment(
            tenant,
            repository_url=request.repository_url,
            repository_name=request.repository_name,
            sbom=request.sbom,
            vex=request.vex,
            source_refs=request.source_refs,
            created_by=request.created_by,
            export_report=request.export_report,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/assessments/{assessment_id}")
def get_maintainer_assessment(
    assessment_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Return a previously generated maintainer assessment."""
    auth = AuthService(session)
    tenant = auth.resolve_private_tenant(token_data=token_data, tenant_id=tenant_id, tenant_slug=tenant_slug)
    auth.assert_tenant_access(tenant, token_data, access="read")
    try:
        return MaintainerAssessmentService(session).get_assessment(tenant, assessment_id=assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/assessments/{assessment_id}/export")
def export_maintainer_assessment(
    assessment_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Create or return the approved report export for an assessment."""
    auth = AuthService(session)
    tenant = auth.resolve_private_tenant(token_data=token_data, tenant_id=tenant_id, tenant_slug=tenant_slug)
    auth.assert_tenant_access(tenant, token_data, access="write")
    try:
        return MaintainerAssessmentService(session).export_assessment(tenant, assessment_id=assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
