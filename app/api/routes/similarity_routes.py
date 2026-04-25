"""V4 specimen behavior similarity + variant diff routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant, require_writable_tenant
from app.services.behavior_similarity_service import BehaviorSimilarityService

router = APIRouter(prefix="/api/v4/specimens", tags=["Sheshnaag V4 Similarity"])


@router.post("/{specimen_id}/embed")
def compute_specimen_embedding(
    specimen_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    """Compute and persist a behavior embedding for the specimen."""

    tenant = require_writable_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug)
    try:
        return BehaviorSimilarityService(session).embed_specimen(
            tenant, specimen_id=specimen_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{specimen_id}/similar")
def list_similar_specimens(
    specimen_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    top_k: int = Query(10, ge=1, le=100),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    """Return tenant-scoped specimens ranked by behavior cosine similarity."""

    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    try:
        return BehaviorSimilarityService(session).find_similar(
            tenant,
            specimen_id=specimen_id,
            top_k=top_k,
            min_score=min_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{specimen_id}/diff/{other_specimen_id}")
def variant_diff(
    specimen_id: int,
    other_specimen_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    """Variant diff: cosine + per-category shared/only_a/only_b feature lists."""

    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=False
    )
    try:
        return BehaviorSimilarityService(session).variant_diff(
            tenant,
            specimen_id_a=specimen_id,
            specimen_id_b=other_specimen_id,
        )
    except ValueError as exc:
        # 404 for not-found, 400 for "must differ"
        status = 400 if str(exc) == "specimens_must_differ" else 404
        raise HTTPException(status_code=status, detail=str(exc)) from exc
