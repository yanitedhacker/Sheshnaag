"""V4 authorization artifact APIs."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.models.capability import AuthorizationArtifact
from app.services.capability_policy import CapabilityPolicy, IssuanceRequest, Reviewer

router = APIRouter(prefix="/api/v4/authorization", tags=["Sheshnaag V4 Authorization"])


def _bound_actor(token_data: TokenData, fallback: str) -> str:
    """Use the JWT subject as the authoritative actor; fall back to the body
    field only when the token is the anonymous dev fallback. Prevents an
    unauthenticated client from forging requester/approver/revoker identity."""

    name = (token_data.username or "").strip()
    if name and name != "anonymous":
        return name
    return fallback


class AuthorizationRequest(BaseModel):
    capability: str
    scope: dict[str, Any] = Field(default_factory=dict)
    requester: str
    reason: str
    reviewers: list[dict[str, Any]] = Field(default_factory=list)
    requested_ttl_seconds: Optional[int] = None
    engagement_ref: Optional[str] = None
    is_admin_approved: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class RevokeRequest(BaseModel):
    actor: str
    reason: str


class ApproveRequest(BaseModel):
    reviewer: str


def _artifact_payload(row: AuthorizationArtifact) -> dict[str, Any]:
    return {
        "artifact_id": row.artifact_id,
        "schema_version": row.schema_version,
        "capability": row.capability,
        "scope": row.scope or {},
        "requester": row.requester or {},
        "reviewers": row.reviewers or [],
        "issued_at": row.issued_at.isoformat() if row.issued_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_by": row.revoked_by,
        "revoke_reason": row.revoke_reason,
        "signer_cert": base64.b64encode(bytes(row.signer_cert or b"")).decode("ascii"),
        "signature": base64.b64encode(bytes(row.signature or b"")).decode("ascii"),
    }


@router.get("")
def list_authorizations(
    capability: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    query = session.query(AuthorizationArtifact).order_by(AuthorizationArtifact.issued_at.desc())
    if capability:
        query = query.filter(AuthorizationArtifact.capability == capability)
    rows = query.all()
    if state == "active":
        rows = [row for row in rows if row.revoked_at is None]
    elif state == "revoked":
        rows = [row for row in rows if row.revoked_at is not None]
    return {"items": [_artifact_payload(row) for row in rows], "count": len(rows)}


@router.post("/request")
def request_authorization(
    request: AuthorizationRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    reviewers = [
        Reviewer(
            reviewer=str(item.get("reviewer") or item.get("name") or ""),
            decision=str(item.get("decision") or "approve"),
        )
        for item in request.reviewers
    ]
    try:
        artifact = CapabilityPolicy(session).issue(
            IssuanceRequest(
                capability=request.capability,
                scope=request.scope,
                requester=_bound_actor(token_data, request.requester),
                reason=request.reason,
                requested_ttl=timedelta(seconds=request.requested_ttl_seconds)
                if request.requested_ttl_seconds
                else None,
                engagement_ref=request.engagement_ref,
                is_admin_approved=request.is_admin_approved,
                extra=request.extra,
            ),
            reviewers,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _artifact_payload(artifact)


@router.post("/{artifact_id}/approve")
def approve_authorization(
    artifact_id: str,
    request: ApproveRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    artifact = session.get(AuthorizationArtifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="authorization_request_not_found")
    payload = _artifact_payload(artifact)
    payload["approval_status"] = "already_issued"
    payload["approved_by"] = _bound_actor(token_data, request.reviewer)
    return payload


@router.post("/{artifact_id}/revoke")
def revoke_authorization(
    artifact_id: str,
    request: RevokeRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    try:
        CapabilityPolicy(session).revoke(
            artifact_id,
            actor=_bound_actor(token_data, request.actor),
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"artifact_id": artifact_id, "revoked": True}


@router.get("/chain/root")
def authorization_chain_root(
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    return CapabilityPolicy(session).latest_root()


@router.get("/chain/verify")
def authorization_chain_verify(
    since: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 — auth gate
):
    result = CapabilityPolicy(session).verify_chain(since=since)
    return {
        "ok": result.ok,
        "last_verified_idx": result.last_verified_idx,
        "first_bad_idx": result.first_bad_idx,
        "reason": result.reason,
    }
