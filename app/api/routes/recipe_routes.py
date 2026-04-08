"""Sheshnaag recipe APIs."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import require_writable_tenant, resolve_tenant
from app.services.sheshnaag_service import SheshnaagService

router = APIRouter(prefix="/api/recipes", tags=["Sheshnaag Recipes"])


class RecipeCreateRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    candidate_id: int
    name: str
    objective: str
    created_by: str
    content: Dict[str, Any] = Field(default_factory=dict)


class RecipeRevisionRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    updated_by: str
    content: Dict[str, Any] = Field(default_factory=dict)


class RecipeApproveRequest(BaseModel):
    tenant_id: Optional[int] = None
    tenant_slug: Optional[str] = None
    reviewer: str


@router.get("")
def list_recipes(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """List recipes."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    return SheshnaagService(session).list_recipes(tenant)


@router.post("")
def create_recipe(request: RecipeCreateRequest, session: Session = Depends(get_sync_session)):
    """Create a recipe and first revision."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).create_recipe(
            tenant,
            candidate_id=request.candidate_id,
            name=request.name,
            objective=request.objective,
            created_by=request.created_by,
            content=request.content,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{recipe_id}")
def get_recipe(
    recipe_id: int,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    """Get a recipe with revisions."""
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    try:
        return SheshnaagService(session).get_recipe(tenant, recipe_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{recipe_id}/revisions")
def add_recipe_revision(recipe_id: int, request: RecipeRevisionRequest, session: Session = Depends(get_sync_session)):
    """Create a new recipe revision."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).add_recipe_revision(
            tenant,
            recipe_id=recipe_id,
            updated_by=request.updated_by,
            content=request.content,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{recipe_id}/revisions/{revision_number}/approve")
def approve_recipe_revision(
    recipe_id: int,
    revision_number: int,
    request: RecipeApproveRequest,
    session: Session = Depends(get_sync_session),
):
    """Approve a recipe revision."""
    tenant = require_writable_tenant(session, tenant_id=request.tenant_id, tenant_slug=request.tenant_slug)
    try:
        return SheshnaagService(session).approve_recipe_revision(
            tenant,
            recipe_id=recipe_id,
            revision_number=revision_number,
            reviewer=request.reviewer,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
