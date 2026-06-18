"""V4 authorization artifact APIs."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.models.capability import (
    AuthorizationArtifact,
    AuthorizationDecisionRecord,
    AuthorizationRequestRecord,
)
from app.services.capability_policy import (
    AuthorizationDecisionResult,
    AuthorizationWorkflowError,
    CapabilityPolicy,
)

router = APIRouter(prefix="/api/v4/authorization", tags=["Sheshnaag V4 Authorization"])


def _bound_actor(token_data: TokenData, fallback: str) -> str:
    """Use the JWT subject as the authoritative actor; fall back to the body
    field only when the token is the anonymous dev fallback. Prevents an
    unauthenticated client from forging requester/approver/revoker identity."""

    name = (token_data.username or "").strip()
    if name and name != "anonymous":
        return name
    return fallback


class PendingAuthorizationRequest(BaseModel):
    capability: str
    action: str
    action_arguments: dict[str, Any]
    requester: str = "ui"
    reason: str = Field(min_length=4, max_length=2000)
    requested_ttl_seconds: int | None = Field(
        default=None,
        gt=0,
        le=31_536_000,
    )
    engagement_ref: str | None = None


class AuthorizationDecisionRequest(BaseModel):
    decision: str
    note: str | None = Field(default=None, max_length=2000)


class RevokeRequest(BaseModel):
    actor: str
    reason: str


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


def _request_payload(
    row: AuthorizationRequestRecord,
    *,
    decisions: Optional[list[AuthorizationDecisionRecord]] = None,
) -> dict[str, Any]:
    return {
        "request_id": row.request_id,
        "capability": row.capability,
        "scope": row.scope or {},
        "action": row.action,
        "action_digest": row.action_digest,
        "requester": row.requester,
        "reason": row.reason,
        "requested_ttl_seconds": row.requested_ttl_seconds,
        "engagement_ref": row.engagement_ref,
        "status": row.status,
        "required_approvals": row.required_approvals,
        "requires_admin_approval": row.requires_admin_approval,
        "artifact_id": row.artifact_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "decisions": [
            {
                "reviewer": item.reviewer,
                "reviewer_roles": item.reviewer_roles or [],
                "decision": item.decision,
                "note": item.note,
                "created_at": item.created_at.isoformat()
                if item.created_at
                else None,
            }
            for item in (decisions or [])
        ],
    }


def _decision_payload(result: AuthorizationDecisionResult) -> dict[str, Any]:
    payload = _request_payload(result.request)
    payload["artifact"] = (
        _artifact_payload(result.artifact) if result.artifact is not None else None
    )
    return payload


def _raise_workflow_http(exc: AuthorizationWorkflowError) -> None:
    code = exc.code
    if code.startswith("unknown_request:"):
        status_code = status.HTTP_404_NOT_FOUND
    elif code.startswith("request_not_pending:") or code in {
        "duplicate_reviewer_decision",
        "requester_cannot_review",
        "request_expired",
    }:
        status_code = status.HTTP_409_CONFLICT
    else:
        status_code = status.HTTP_400_BAD_REQUEST
    raise HTTPException(status_code=status_code, detail=code) from exc


@router.get("")
def list_authorizations(
    capability: str | None = Query(None),
    state: str | None = Query(None),
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


@router.get("/requests")
def list_authorization_requests(
    capability: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 - auth gate
):
    query = session.query(AuthorizationRequestRecord).order_by(
        AuthorizationRequestRecord.created_at.desc()
    )
    if capability:
        query = query.filter(AuthorizationRequestRecord.capability == capability)
    if state:
        query = query.filter(AuthorizationRequestRecord.status == state)
    rows = query.limit(500).all()
    request_ids = [row.request_id for row in rows]
    decisions_by_request: dict[str, list[AuthorizationDecisionRecord]] = {
        request_id: [] for request_id in request_ids
    }
    if request_ids:
        decisions = (
            session.query(AuthorizationDecisionRecord)
            .filter(AuthorizationDecisionRecord.request_id.in_(request_ids))
            .order_by(AuthorizationDecisionRecord.created_at.asc())
            .all()
        )
        for decision in decisions:
            decisions_by_request.setdefault(decision.request_id, []).append(decision)
    return {
        "items": [
            _request_payload(
                row,
                decisions=decisions_by_request.get(row.request_id, []),
            )
            for row in rows
        ],
        "count": len(rows),
    }


@router.post("/requests", status_code=status.HTTP_201_CREATED)
def create_authorization_request(
    request: PendingAuthorizationRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    policy = CapabilityPolicy(session)
    actor = _bound_actor(token_data, request.requester)
    if actor != "anonymous" and not policy.permitted_requester_for(
        request.capability, token_data.roles
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="requester_role_not_permitted",
        )
    try:
        row = policy.create_request(
            capability=request.capability,
            action=request.action,
            arguments=request.action_arguments,
            requester=actor,
            reason=request.reason,
            requested_ttl=timedelta(seconds=request.requested_ttl_seconds)
            if request.requested_ttl_seconds is not None
            else None,
            engagement_ref=request.engagement_ref,
        )
    except AuthorizationWorkflowError as exc:
        _raise_workflow_http(exc)
    return _request_payload(row)


@router.post("/requests/{request_id}/decisions")
def decide_authorization_request(
    request_id: str,
    request: AuthorizationDecisionRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    reviewer = (token_data.username or "").strip() or "anonymous"
    try:
        result = CapabilityPolicy(session).record_decision(
            request_id,
            reviewer=reviewer,
            reviewer_roles=token_data.roles,
            decision=request.decision,
            note=request.note,
        )
    except AuthorizationWorkflowError as exc:
        _raise_workflow_http(exc)
    return _decision_payload(result)


@router.post("/request")
def removed_unsafe_authorization_request(
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 - auth gate
):
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="unsafe_authorization_flow_removed",
    )


@router.post("/{artifact_id}/approve")
def removed_artifact_approval(
    artifact_id: str,
    token_data: TokenData = Depends(verify_token),  # noqa: ARG001 - auth gate
):
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail=f"artifact_approval_removed:{artifact_id}",
    )


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
    since: int | None = Query(None),
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
