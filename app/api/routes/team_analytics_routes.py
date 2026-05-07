"""V5 W3a — team analytics endpoints.

Five read-only endpoints under ``/api/v5/analytics`` that surface
the aggregations computed by
:class:`app.services.team_analytics.TeamAnalyticsService`.

Reads are gated to ``analytics.read`` (senior_analyst, reviewer,
lab_lead). The tenant is resolved via the standard
``resolve_tenant`` helper so callers can pass ``tenant_slug`` or
``tenant_id`` query parameters; absent both, the service falls back
to the configured demo tenant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import require_permission
from app.core.tenancy import resolve_tenant
from app.services.team_analytics import TeamAnalyticsService


router = APIRouter(
    prefix="/api/v5/analytics", tags=["Sheshnaag V5 Team Analytics"]
)


# ----- response models -----


class MttrAnalystEntry(BaseModel):
    count: float
    mean_seconds: float
    p50_seconds: float
    p95_seconds: float


class MttrResponse(BaseModel):
    window_start: datetime
    window_end: datetime
    sample_count: int
    overall_mean_seconds: Optional[float]
    overall_p50_seconds: Optional[float]
    overall_p95_seconds: Optional[float]
    by_analyst: Dict[str, MttrAnalystEntry]


class ReviewLatencyResponse(BaseModel):
    window_start: datetime
    window_end: datetime
    sample_count: int
    overall_mean_seconds: Optional[float]
    overall_p50_seconds: Optional[float]
    overall_p95_seconds: Optional[float]
    by_reviewer: Dict[str, MttrAnalystEntry]


class AttackDriftResponse(BaseModel):
    window_seconds: int
    current_window: List[str]
    prior_window: List[str]
    new_in_current: List[str]
    dropped_from_prior: List[str]


class CapabilityUsageResponse(BaseModel):
    window_start: datetime
    window_end: datetime
    by_capability: Dict[str, int]
    by_actor: Dict[str, Dict[str, int]]
    distinct_actors: int


class QueueAgingResponse(BaseModel):
    generated_at: datetime
    bucket_boundaries_days: List[float]
    bucket_labels: List[str]
    state_buckets: Dict[str, List[int]]


class AnalyticsSummaryResponse(BaseModel):
    """Top-of-page convenience: header counts + window. UI uses it
    as the cheap-to-render landing card."""

    tenant_id: int
    window_days: int
    mttr: MttrResponse
    review_latency: ReviewLatencyResponse
    queue_aging: QueueAgingResponse
    ai_session_volume: Dict[str, int]


_BUCKET_LABELS = ["<1d", "1-3d", "3-7d", "7-14d", ">14d"]


def _service(session: Session) -> TeamAnalyticsService:
    return TeamAnalyticsService(session)


@router.get("/mttr", response_model=MttrResponse)
def mttr(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    window_days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> MttrResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    report = _service(session).mttr(tenant.id, window_days=window_days)
    return MttrResponse(
        window_start=report.window_start,
        window_end=report.window_end,
        sample_count=report.sample_count,
        overall_mean_seconds=report.overall_mean_seconds,
        overall_p50_seconds=report.overall_p50_seconds,
        overall_p95_seconds=report.overall_p95_seconds,
        by_analyst={
            actor: MttrAnalystEntry(**vals) for actor, vals in report.by_analyst.items()
        },
    )


@router.get("/review-latency", response_model=ReviewLatencyResponse)
def review_latency(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    window_days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> ReviewLatencyResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    report = _service(session).review_latency(tenant.id, window_days=window_days)
    return ReviewLatencyResponse(
        window_start=report.window_start,
        window_end=report.window_end,
        sample_count=report.sample_count,
        overall_mean_seconds=report.overall_mean_seconds,
        overall_p50_seconds=report.overall_p50_seconds,
        overall_p95_seconds=report.overall_p95_seconds,
        by_reviewer={
            actor: MttrAnalystEntry(**vals) for actor, vals in report.by_reviewer.items()
        },
    )


@router.get("/attack-drift", response_model=AttackDriftResponse)
def attack_drift(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    window_days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> AttackDriftResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    report = _service(session).attack_drift(tenant.id, window_days=window_days)
    return AttackDriftResponse(
        window_seconds=report.window_seconds,
        current_window=report.current_window,
        prior_window=report.prior_window,
        new_in_current=report.new_in_current,
        dropped_from_prior=report.dropped_from_prior,
    )


@router.get("/capability-usage", response_model=CapabilityUsageResponse)
def capability_usage(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    window_days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> CapabilityUsageResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    report = _service(session).capability_usage(tenant.id, window_days=window_days)
    return CapabilityUsageResponse(
        window_start=report.window_start,
        window_end=report.window_end,
        by_capability=report.by_capability,
        by_actor=report.by_actor,
        distinct_actors=report.distinct_actors,
    )


@router.get("/queue-aging", response_model=QueueAgingResponse)
def queue_aging(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> QueueAgingResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    report = _service(session).queue_aging(tenant.id)
    return QueueAgingResponse(
        generated_at=report.generated_at,
        bucket_boundaries_days=report.bucket_boundaries_days,
        bucket_labels=_BUCKET_LABELS,
        state_buckets=report.state_buckets,
    )


@router.get("/summary", response_model=AnalyticsSummaryResponse)
def summary(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    window_days: int = Query(30, ge=1, le=365),
    session: Session = Depends(get_sync_session),
    _td=Depends(require_permission("analytics.read")),
) -> AnalyticsSummaryResponse:
    tenant = resolve_tenant(
        session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True
    )
    svc = _service(session)
    mttr_r = svc.mttr(tenant.id, window_days=window_days)
    rev_r = svc.review_latency(tenant.id, window_days=window_days)
    qa_r = svc.queue_aging(tenant.id)
    ai_vol = svc.ai_session_volume(tenant.id, window_days=window_days)

    return AnalyticsSummaryResponse(
        tenant_id=tenant.id,
        window_days=window_days,
        mttr=MttrResponse(
            window_start=mttr_r.window_start,
            window_end=mttr_r.window_end,
            sample_count=mttr_r.sample_count,
            overall_mean_seconds=mttr_r.overall_mean_seconds,
            overall_p50_seconds=mttr_r.overall_p50_seconds,
            overall_p95_seconds=mttr_r.overall_p95_seconds,
            by_analyst={
                actor: MttrAnalystEntry(**vals)
                for actor, vals in mttr_r.by_analyst.items()
            },
        ),
        review_latency=ReviewLatencyResponse(
            window_start=rev_r.window_start,
            window_end=rev_r.window_end,
            sample_count=rev_r.sample_count,
            overall_mean_seconds=rev_r.overall_mean_seconds,
            overall_p50_seconds=rev_r.overall_p50_seconds,
            overall_p95_seconds=rev_r.overall_p95_seconds,
            by_reviewer={
                actor: MttrAnalystEntry(**vals)
                for actor, vals in rev_r.by_reviewer.items()
            },
        ),
        queue_aging=QueueAgingResponse(
            generated_at=qa_r.generated_at,
            bucket_boundaries_days=qa_r.bucket_boundaries_days,
            bucket_labels=_BUCKET_LABELS,
            state_buckets=qa_r.state_buckets,
        ),
        ai_session_volume=ai_vol,
    )
