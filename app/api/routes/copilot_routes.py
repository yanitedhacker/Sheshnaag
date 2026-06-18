"""Grounded copilot APIs."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.copilot_service import CopilotService

router = APIRouter(prefix="/api/copilot", tags=["Copilot"])


class CopilotQueryRequest(BaseModel):
    query: str = Field(..., min_length=3)
    tenant_slug: str | None = None
    tenant_id: int | None = None


@router.post("/query")
def query_copilot(
    request: CopilotQueryRequest,
    session: Session = Depends(get_sync_session),
):
    """Answer supported security questions with grounded evidence."""
    tenant = resolve_tenant(
        session,
        tenant_id=request.tenant_id,
        tenant_slug=request.tenant_slug,
        default_to_demo=True,
    )
    service = CopilotService(session)
    return service.answer(tenant, request.query)
