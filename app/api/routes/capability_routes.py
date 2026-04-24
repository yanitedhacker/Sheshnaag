"""V4 capability-check APIs."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.services.capability_policy import CapabilityPolicy

router = APIRouter(prefix="/api/v4/capability", tags=["Sheshnaag V4 Capability"])


def _parse_scope(scope: Optional[str]) -> dict:
    if not scope:
        return {}
    try:
        parsed = json.loads(scope)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="scope_must_be_json") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="scope_must_be_object")
    return parsed


@router.get("/check")
def check_capability(
    capability: str = Query(...),
    scope: Optional[str] = Query(None),
    actor: str = Query("anonymous"),
    session: Session = Depends(get_sync_session),
):
    decision = CapabilityPolicy(session).evaluate(
        capability=capability,
        scope=_parse_scope(scope),
        actor=actor,
    )
    return {
        "permitted": decision.permitted,
        "reason": decision.reason,
        "artifact_id": decision.artifact_id,
    }
