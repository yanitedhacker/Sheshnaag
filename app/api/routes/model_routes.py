"""Model trust APIs."""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import verify_token_optional, TokenData
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.auth_service import AuthService
from app.services.governance_service import GovernanceService
from app.services.model_trust_service import ModelTrustService

router = APIRouter(prefix="/api/model", tags=["Model Trust"])


class FeedbackRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    action_id: str = Field(..., min_length=3)
    feedback_type: str = Field(..., min_length=3)
    note: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


@router.get("/trust")
def get_model_trust(
    session: Session = Depends(get_sync_session),
):
    """Return model trust and drift metadata."""
    service = ModelTrustService(session)
    return service.get_trust_snapshot()


@router.get("/feedback")
def get_feedback(
    tenant_slug: Optional[str] = None,
    tenant_id: Optional[int] = None,
    session: Session = Depends(get_sync_session),
):
    """List recent analyst feedback items for a tenant."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    service = GovernanceService(session)
    return service.list_feedback(tenant)


@router.post("/feedback")
def submit_feedback(
    request: FeedbackRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Capture analyst feedback for a private tenant action."""
    auth_service = AuthService(session)
    if request.tenant_id is None and request.tenant_slug is None:
        tenant = auth_service.resolve_private_tenant(token_data=token_data)
    else:
        tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    auth_service.assert_tenant_access(tenant, token_data, access="write")

    actor = auth_service.get_user_from_token(token_data)
    service = GovernanceService(session)
    return service.submit_feedback(
        tenant,
        action_id=request.action_id,
        feedback_type=request.feedback_type,
        note=request.note,
        actor=actor,
        metadata=request.metadata,
    )
