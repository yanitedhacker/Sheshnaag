"""Sheshnaag defensive artifact APIs."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/artifacts", tags=["Sheshnaag Artifacts"])


class ArtifactReviewRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    artifact_family: str
    artifact_id: int
    decision: str
    reviewer: str
    rationale: Optional[str] = None
    correction_note: Optional[str] = None
    supersedes_artifact_id: Optional[int] = None


class ArtifactFeedbackRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    artifact_family: str
    artifact_id: int
    reviewer: str
    feedback_type: str = "false_positive"
    note: Optional[str] = None


@router.get("")
def list_artifacts(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List generated detection and mitigation artifacts."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_artifacts(tenant, run_id=run_id)


@router.post("/review")
def review_artifact(request: ArtifactReviewRequest, session: Session = Depends(get_sync_session)):
    """Advance an artifact through the review state machine."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).review_artifact(
            tenant,
            artifact_family=request.artifact_family,
            artifact_id=request.artifact_id,
            decision=request.decision,
            reviewer=request.reviewer,
            rationale=request.rationale,
            correction_note=request.correction_note,
            supersedes_artifact_id=request.supersedes_artifact_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/feedback")
def add_artifact_feedback(request: ArtifactFeedbackRequest, session: Session = Depends(get_sync_session)):
    """Persist explicit operator feedback for an artifact."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).add_artifact_feedback(
            tenant,
            artifact_family=request.artifact_family,
            artifact_id=request.artifact_id,
            reviewer=request.reviewer,
            feedback_type=request.feedback_type,
            note=request.note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
