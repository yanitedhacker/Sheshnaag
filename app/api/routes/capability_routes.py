"""V4 capability-check APIs."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.services.capability_policy import CAPABILITIES, CapabilityPolicy

router = APIRouter(prefix="/api/v4/capability", tags=["Sheshnaag V4 Capability"])


def _parse_scope(scope: str | None) -> dict:
    if not scope:
        return {}
    try:
        parsed = json.loads(scope)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="scope_must_be_json") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="scope_must_be_object")
    return parsed


@router.get("/registry")
def capability_registry(
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    """Return the live capability taxonomy for AuthorizationCenter UI."""
    items = []
    for name, cap in sorted(CAPABILITIES.items()):
        items.append(
            {
                "name": name,
                "default": cap.default,
                "review_kind": cap.review_kind,
                "max_ttl_seconds": int(cap.max_ttl.total_seconds()),
                "requires_engagement_doc": cap.requires_engagement_doc,
                "requester_roles": sorted(cap.requester_roles) if cap.requester_roles else None,
            }
        )
    return {"items": items, "count": len(items)}


@router.get("/check")
def check_capability(
    capability: str = Query(...),
    scope: str | None = Query(None),
    actor: str = Query("anonymous"),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    # Bind actor to the JWT subject when one is presented; otherwise fall back
    # to the (untrusted) query parameter for the dev/anonymous mode. Without
    # this, an unauthenticated client could probe capability decisions for
    # arbitrary identities.
    bound_username = (token_data.username or "").strip()
    effective_actor = bound_username if bound_username and bound_username != "anonymous" else actor
    decision = CapabilityPolicy(session).evaluate(
        capability=capability,
        scope=_parse_scope(scope),
        actor=effective_actor,
    )
    return {
        "permitted": decision.permitted,
        "reason": decision.reason,
        "artifact_id": decision.artifact_id,
    }
