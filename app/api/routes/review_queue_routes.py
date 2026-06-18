"""Sheshnaag cross-entity review queue APIs."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/review-queue", tags=["Sheshnaag Review Queue"])


@router.get("")
def list_review_queue(
    tenant_slug: str | None = Query(None),
    tenant_id: int | None = Query(None),
    entity_type: str | None = Query(None),
    status: str | None = Query(None),
    run_id: int | None = Query(None),
    reviewer: str | None = Query(None),
    needs_attention: bool | None = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List normalized reviewable entities across runs, evidence, artifacts, and bundles."""
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    return SheshnaagService(session).list_review_queue(
        tenant,
        entity_type=entity_type,
        status=status,
        run_id=run_id,
        reviewer=reviewer,
        needs_attention=needs_attention,
    )
