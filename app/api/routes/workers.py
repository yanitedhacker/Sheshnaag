"""V5 W1b worker pool API routes.

  * ``POST /api/v5/workers/enrollment-tokens`` (lab_lead) — mint
    single-use token; returned plaintext exactly once.
  * ``POST /api/v5/workers/bootstrap`` (no auth — token-gated) —
    consume token, sign CSR, register worker, return cert + CA + Redis URL.
  * ``POST /api/v5/workers/{id}/heartbeat`` (no auth — cert-gated at
    Redis layer) — refresh last_heartbeat; returns current state so
    the worker sees drain signals.
  * ``POST /api/v5/workers/{id}/drain`` (lab_lead) — flip state to
    ``draining``.
  * ``GET /api/v5/workers`` (any authenticated) — list fleet.
  * ``GET /api/v5/workers/{id}`` (any authenticated) — single worker.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_sync_session
from app.core.security import (
    TokenData,
    require_role,
    verify_token,
)
from app.services.worker_pool import (
    EnrollmentTokenInvalidError,
    WorkerNotFoundError,
    WorkerPoolService,
)


router = APIRouter(prefix="/api/v5/workers", tags=["Sheshnaag V5 Worker Pool"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class EnrollmentTokenIssueResponse(BaseModel):
    token: str
    expires_at: datetime


class BootstrapRequest(BaseModel):
    enrollment_token: str
    csr_pem: str
    capability_flags: List[str] = Field(default_factory=list)


class BootstrapResponse(BaseModel):
    worker_id: int
    worker_uuid: str
    cert_pem: str
    ca_pem: str
    redis_url: str
    not_after: datetime


class HeartbeatRequest(BaseModel):
    capability_flags: Optional[List[str]] = None


class HeartbeatResponse(BaseModel):
    worker_id: int
    state: str
    last_heartbeat: Optional[datetime]


class WorkerSummary(BaseModel):
    id: int
    worker_uuid: str
    cert_fingerprint: str
    capability_flags: List[str]
    state: str
    last_heartbeat: Optional[datetime]
    enrolled_at: datetime
    enrolled_by: str


class DrainResponse(BaseModel):
    worker_id: int
    state: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summary(worker) -> WorkerSummary:
    return WorkerSummary(
        id=worker.id,
        worker_uuid=worker.worker_uuid,
        cert_fingerprint=worker.cert_fingerprint,
        capability_flags=list(worker.capability_flags or []),
        state=worker.state,
        last_heartbeat=worker.last_heartbeat,
        enrolled_at=worker.enrolled_at,
        enrolled_by=worker.enrolled_by,
    )


def _worker_redis_url() -> str:
    """Resolve the URL workers use to reach Redis.

    Per Phase 0 decision #2, control-plane <-> Redis stays on
    ``redis://`` (loopback), but worker <-> Redis is ``rediss://``. The
    worker URL is read from ``SHESHNAAG_WORKER_REDIS_URL`` env, falling
    back to a TLS variant of ``settings.redis_url``.
    """
    import os as _os

    explicit = _os.environ.get("SHESHNAAG_WORKER_REDIS_URL")
    if explicit:
        return explicit
    base = settings.redis_url
    if base.startswith("rediss://"):
        return base
    if base.startswith("redis://"):
        return "rediss://" + base[len("redis://") :]
    return base


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenIssueResponse,
    dependencies=[Depends(require_role("lab_lead"))],
)
def issue_enrollment_token(
    token_data: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> EnrollmentTokenIssueResponse:
    svc = WorkerPoolService(session)
    actor = token_data.username or "lab_lead"
    issued = svc.issue_enrollment_token(issued_by=actor)
    return EnrollmentTokenIssueResponse(
        token=issued.token, expires_at=issued.expires_at
    )


@router.post("/bootstrap", response_model=BootstrapResponse)
def bootstrap_worker(
    req: BootstrapRequest,
    session: Session = Depends(get_sync_session),
) -> BootstrapResponse:
    """No JWT required: the enrollment_token IS the auth.

    This endpoint is the one place a *non-authenticated* HTTP caller
    can mutate the worker registry. Single-use token consumption keeps
    that surface tight.
    """
    svc = WorkerPoolService(session)
    try:
        result = svc.bootstrap(
            enrollment_token=req.enrollment_token,
            csr_pem=req.csr_pem,
            capability_flags=req.capability_flags,
            redis_url=_worker_redis_url(),
        )
    except EnrollmentTokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(e)
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e

    return BootstrapResponse(
        worker_id=result.worker_id,
        worker_uuid=result.worker_uuid,
        cert_pem=result.cert_pem,
        ca_pem=result.ca_pem,
        redis_url=result.redis_url,
        not_after=result.not_after,
    )


@router.post(
    "/{worker_id}/heartbeat", response_model=HeartbeatResponse
)
def heartbeat(
    worker_id: int,
    req: HeartbeatRequest,
    session: Session = Depends(get_sync_session),
) -> HeartbeatResponse:
    """No JWT — the worker authenticates via mTLS at the Redis layer.

    The control plane trusts that a request reaching this endpoint
    over HTTPS came from a worker that holds a CA-signed cert (the
    HTTP termination layer / reverse proxy enforces mTLS in
    production). For dev, the endpoint is open by design.
    """
    svc = WorkerPoolService(session)
    try:
        worker = svc.heartbeat(
            worker_id, capability_flags=req.capability_flags
        )
    except WorkerNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
        ) from e
    return HeartbeatResponse(
        worker_id=worker.id,
        state=worker.state,
        last_heartbeat=worker.last_heartbeat,
    )


@router.post(
    "/{worker_id}/drain",
    response_model=DrainResponse,
    dependencies=[Depends(require_role("lab_lead"))],
)
def drain_worker(
    worker_id: int,
    session: Session = Depends(get_sync_session),
) -> DrainResponse:
    svc = WorkerPoolService(session)
    try:
        worker = svc.drain(worker_id)
    except WorkerNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
        ) from e
    return DrainResponse(worker_id=worker.id, state=worker.state)


@router.get("", response_model=List[WorkerSummary])
def list_workers(
    _td: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> List[WorkerSummary]:
    svc = WorkerPoolService(session)
    return [_summary(w) for w in svc.list_workers()]


@router.get("/{worker_id}", response_model=WorkerSummary)
def get_worker(
    worker_id: int,
    _td: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> WorkerSummary:
    svc = WorkerPoolService(session)
    try:
        return _summary(svc.get_worker(worker_id))
    except WorkerNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(e)
        ) from e
