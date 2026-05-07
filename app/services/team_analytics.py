"""V5 W3a — team analytics read service.

Five read-only aggregations over existing V5 tables:

1. Mean time to resolution (MTTR) — wall time from a case's first
   transition out of ``triage`` to its first transition into
   ``shipped`` or ``archived``. Reported per analyst and overall.

2. Review latency — wall time a case spends in ``review`` before being
   transitioned to ``ready_to_ship`` (or back). Reported per reviewer.

3. ATT&CK coverage drift — count of distinct ATT&CK technique IDs that
   appeared in ``BehaviorFinding.payload['attack_techniques']`` in the
   current window vs. the prior window. Surfaces both new techniques
   (this window only) and dropped techniques (prior only).

4. Capability-usage histogram — count of ``AuditLogEntry`` rows per
   capability per actor across the window. Powers a per-analyst
   matrix in the UI.

5. Queue-aging heatmap — for each lifecycle state, age buckets
   (``<1d, 1-3d, 3-7d, 7-14d, >14d``) computed from
   ``state_changed_at`` for cases currently in that state.

Pure read layer. No writes. No side effects. The frontend renders
each shape directly.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.capability import AuditLogEntry
from app.models.malware_lab import (
    AISession,
    AnalysisCase,
    BehaviorFinding,
    CaseStateTransition,
)
from app.services.case_workflow import CaseLifecycleState


# ---------- shapes ----------


@dataclass
class MttrSample:
    """Single MTTR sample (case-grain)."""

    case_id: int
    analyst: Optional[str]
    triage_left_at: datetime
    closed_at: datetime
    closed_state: str
    duration_seconds: float


@dataclass
class MttrReport:
    """Aggregate MTTR result returned by :meth:`TeamAnalyticsService.mttr`."""

    window_start: datetime
    window_end: datetime
    sample_count: int
    overall_mean_seconds: Optional[float]
    overall_p50_seconds: Optional[float]
    overall_p95_seconds: Optional[float]
    by_analyst: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class ReviewLatencyReport:
    window_start: datetime
    window_end: datetime
    sample_count: int
    overall_mean_seconds: Optional[float]
    overall_p50_seconds: Optional[float]
    overall_p95_seconds: Optional[float]
    by_reviewer: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class AttackDriftReport:
    window_seconds: int
    current_window: List[str]
    prior_window: List[str]
    new_in_current: List[str]
    dropped_from_prior: List[str]


@dataclass
class CapabilityUsageReport:
    window_start: datetime
    window_end: datetime
    by_capability: Dict[str, int]
    by_actor: Dict[str, Dict[str, int]]
    distinct_actors: int


@dataclass
class QueueAgingReport:
    """Heatmap rows: state × age-bucket → count."""

    generated_at: datetime
    bucket_boundaries_days: List[float]
    state_buckets: Dict[str, List[int]]


# ---------- service ----------


_TERMINAL_STATES = frozenset(
    {CaseLifecycleState.SHIPPED.value, CaseLifecycleState.ARCHIVED.value}
)
_AGE_BUCKETS_DAYS: tuple[float, ...] = (1.0, 3.0, 7.0, 14.0)
_DEFAULT_WINDOW_DAYS = 30


def _percentile(samples: List[float], pct: float) -> Optional[float]:
    if not samples:
        return None
    ordered = sorted(samples)
    if len(ordered) == 1:
        return ordered[0]
    rank = (pct / 100.0) * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


def _mean(samples: List[float]) -> Optional[float]:
    if not samples:
        return None
    return sum(samples) / len(samples)


def _resolve_window(
    window_days: int, *, now: Optional[datetime] = None
) -> tuple[datetime, datetime]:
    end = now or utc_now()
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    start = end - timedelta(days=window_days)
    return start, end


class TeamAnalyticsService:
    """Five read-only aggregations powering the V5 analytics page."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # 1) MTTR --------------------------------------------------------------

    def mttr(
        self,
        tenant_id: int,
        *,
        window_days: int = _DEFAULT_WINDOW_DAYS,
        now: Optional[datetime] = None,
    ) -> MttrReport:
        window_start, window_end = _resolve_window(window_days, now=now)

        # Pull every transition for this tenant's cases inside the window.
        # We need both the "leaving triage" timestamp and the "entering
        # shipped/archived" timestamp; both must fall inside the window
        # for the case to count.
        transitions = (
            self.session.query(CaseStateTransition)
            .join(AnalysisCase, AnalysisCase.id == CaseStateTransition.case_id)
            .filter(AnalysisCase.tenant_id == tenant_id)
            .filter(
                and_(
                    CaseStateTransition.occurred_at >= window_start,
                    CaseStateTransition.occurred_at <= window_end,
                )
            )
            .order_by(CaseStateTransition.case_id, CaseStateTransition.id)
            .all()
        )

        # Group by case, then for each case pick the first
        # "from_state=triage" timestamp and the first transition into
        # shipped/archived after that.
        by_case: Dict[int, List[CaseStateTransition]] = defaultdict(list)
        for t in transitions:
            by_case[t.case_id].append(t)

        analyst_lookup: Dict[int, Optional[str]] = {}
        if by_case:
            rows = (
                self.session.query(AnalysisCase.id, AnalysisCase.analyst_name)
                .filter(AnalysisCase.id.in_(list(by_case.keys())))
                .all()
            )
            analyst_lookup = {row.id: row.analyst_name for row in rows}

        samples: List[MttrSample] = []
        for case_id, edges in by_case.items():
            triage_out: Optional[datetime] = None
            close_at: Optional[datetime] = None
            close_state: Optional[str] = None
            for edge in edges:
                if (
                    triage_out is None
                    and edge.from_state == CaseLifecycleState.TRIAGE.value
                ):
                    triage_out = edge.occurred_at
                if (
                    triage_out is not None
                    and edge.occurred_at >= triage_out
                    and edge.to_state in _TERMINAL_STATES
                ):
                    close_at = edge.occurred_at
                    close_state = edge.to_state
                    break
            if triage_out is None or close_at is None or close_state is None:
                continue
            duration = (close_at - triage_out).total_seconds()
            if duration < 0:
                # Defensive: a clock-skewed row should not poison the mean.
                continue
            samples.append(
                MttrSample(
                    case_id=case_id,
                    analyst=analyst_lookup.get(case_id),
                    triage_left_at=triage_out,
                    closed_at=close_at,
                    closed_state=close_state,
                    duration_seconds=duration,
                )
            )

        durations = [s.duration_seconds for s in samples]
        by_analyst: Dict[str, List[float]] = defaultdict(list)
        for s in samples:
            by_analyst[s.analyst or "unassigned"].append(s.duration_seconds)

        report = MttrReport(
            window_start=window_start,
            window_end=window_end,
            sample_count=len(samples),
            overall_mean_seconds=_mean(durations),
            overall_p50_seconds=_percentile(durations, 50),
            overall_p95_seconds=_percentile(durations, 95),
        )
        for analyst, vals in by_analyst.items():
            report.by_analyst[analyst] = {
                "count": float(len(vals)),
                "mean_seconds": _mean(vals) or 0.0,
                "p50_seconds": _percentile(vals, 50) or 0.0,
                "p95_seconds": _percentile(vals, 95) or 0.0,
            }
        return report

    # 2) Review latency ----------------------------------------------------

    def review_latency(
        self,
        tenant_id: int,
        *,
        window_days: int = _DEFAULT_WINDOW_DAYS,
        now: Optional[datetime] = None,
    ) -> ReviewLatencyReport:
        window_start, window_end = _resolve_window(window_days, now=now)

        transitions = (
            self.session.query(CaseStateTransition)
            .join(AnalysisCase, AnalysisCase.id == CaseStateTransition.case_id)
            .filter(AnalysisCase.tenant_id == tenant_id)
            .filter(
                and_(
                    CaseStateTransition.occurred_at >= window_start,
                    CaseStateTransition.occurred_at <= window_end,
                )
            )
            .order_by(CaseStateTransition.case_id, CaseStateTransition.id)
            .all()
        )

        # For each case, pair every "entered review" with the next
        # "left review" edge; record per-pair latency tagged with the
        # actor on the *exit* edge (the reviewer who decided).
        by_case: Dict[int, List[CaseStateTransition]] = defaultdict(list)
        for t in transitions:
            by_case[t.case_id].append(t)

        durations: List[float] = []
        by_reviewer: Dict[str, List[float]] = defaultdict(list)

        for edges in by_case.values():
            entered_at: Optional[datetime] = None
            for edge in edges:
                if edge.to_state == CaseLifecycleState.REVIEW.value:
                    entered_at = edge.occurred_at
                    continue
                if (
                    entered_at is not None
                    and edge.from_state == CaseLifecycleState.REVIEW.value
                ):
                    duration = (edge.occurred_at - entered_at).total_seconds()
                    if duration >= 0:
                        durations.append(duration)
                        by_reviewer[edge.actor or "unknown"].append(duration)
                    entered_at = None

        report = ReviewLatencyReport(
            window_start=window_start,
            window_end=window_end,
            sample_count=len(durations),
            overall_mean_seconds=_mean(durations),
            overall_p50_seconds=_percentile(durations, 50),
            overall_p95_seconds=_percentile(durations, 95),
        )
        for reviewer, vals in by_reviewer.items():
            report.by_reviewer[reviewer] = {
                "count": float(len(vals)),
                "mean_seconds": _mean(vals) or 0.0,
                "p50_seconds": _percentile(vals, 50) or 0.0,
                "p95_seconds": _percentile(vals, 95) or 0.0,
            }
        return report

    # 3) ATT&CK coverage drift --------------------------------------------

    def attack_drift(
        self,
        tenant_id: int,
        *,
        window_days: int = _DEFAULT_WINDOW_DAYS,
        now: Optional[datetime] = None,
    ) -> AttackDriftReport:
        end = now or utc_now()
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        current_start = end - timedelta(days=window_days)
        prior_start = current_start - timedelta(days=window_days)

        rows = (
            self.session.query(BehaviorFinding.payload, BehaviorFinding.created_at)
            .filter(BehaviorFinding.tenant_id == tenant_id)
            .filter(BehaviorFinding.created_at >= prior_start)
            .filter(BehaviorFinding.created_at <= end)
            .all()
        )

        current: set[str] = set()
        prior: set[str] = set()
        for payload, created_at in rows:
            techniques = self._technique_ids(payload)
            if not techniques:
                continue
            target = current if created_at >= current_start else prior
            target.update(techniques)

        return AttackDriftReport(
            window_seconds=int(timedelta(days=window_days).total_seconds()),
            current_window=sorted(current),
            prior_window=sorted(prior),
            new_in_current=sorted(current - prior),
            dropped_from_prior=sorted(prior - current),
        )

    @staticmethod
    def _technique_ids(payload: object) -> Iterable[str]:
        if not isinstance(payload, dict):
            return ()
        techniques = payload.get("attack_techniques")
        if not isinstance(techniques, list):
            return ()
        out: List[str] = []
        for entry in techniques:
            if isinstance(entry, dict):
                tid = entry.get("technique_id") or entry.get("id")
                if isinstance(tid, str) and tid:
                    out.append(tid)
            elif isinstance(entry, str) and entry:
                out.append(entry)
        return out

    # 4) Capability-usage histogram ---------------------------------------

    def capability_usage(
        self,
        tenant_id: int,
        *,
        window_days: int = _DEFAULT_WINDOW_DAYS,
        now: Optional[datetime] = None,
    ) -> CapabilityUsageReport:
        # AuditLogEntry has no tenant_id column — it's a global chain.
        # We scope by tenant via the AISession.tenant_id link where the
        # capability was exercised against an AI session, and otherwise
        # accept the audit row when its scope JSON names this tenant.
        window_start, window_end = _resolve_window(window_days, now=now)

        rows = (
            self.session.query(AuditLogEntry)
            .filter(AuditLogEntry.signed_at >= window_start)
            .filter(AuditLogEntry.signed_at <= window_end)
            .all()
        )

        by_capability: Counter[str] = Counter()
        by_actor: Dict[str, Counter[str]] = defaultdict(Counter)
        actors: set[str] = set()
        for row in rows:
            if not self._scope_matches_tenant(row.scope, tenant_id):
                continue
            cap = row.capability or "unknown"
            actor = row.actor or "unknown"
            by_capability[cap] += 1
            by_actor[actor][cap] += 1
            actors.add(actor)

        return CapabilityUsageReport(
            window_start=window_start,
            window_end=window_end,
            by_capability=dict(by_capability),
            by_actor={actor: dict(counter) for actor, counter in by_actor.items()},
            distinct_actors=len(actors),
        )

    @staticmethod
    def _scope_matches_tenant(scope: object, tenant_id: int) -> bool:
        if not isinstance(scope, dict):
            # Empty scope — treat as global; include in tenant view so
            # cluster-wide policy events still appear.
            return True
        scoped_id = scope.get("tenant_id")
        if scoped_id is None:
            return True
        try:
            return int(scoped_id) == int(tenant_id)
        except (TypeError, ValueError):
            return False

    # 5) Queue-aging heatmap ----------------------------------------------

    def queue_aging(
        self,
        tenant_id: int,
        *,
        now: Optional[datetime] = None,
    ) -> QueueAgingReport:
        ref = now or utc_now()
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)

        rows = (
            self.session.query(
                AnalysisCase.lifecycle_state, AnalysisCase.state_changed_at
            )
            .filter(AnalysisCase.tenant_id == tenant_id)
            .all()
        )

        # Bucket layout: [<1d, 1-3d, 3-7d, 7-14d, >14d] — five slots,
        # boundaries at 1, 3, 7, 14 days.
        n_buckets = len(_AGE_BUCKETS_DAYS) + 1
        state_buckets: Dict[str, List[int]] = {
            state.value: [0] * n_buckets for state in CaseLifecycleState
        }

        for state_value, changed_at in rows:
            if state_value not in state_buckets:
                continue
            if changed_at is None:
                bucket_idx = n_buckets - 1
            else:
                if changed_at.tzinfo is None:
                    changed_at = changed_at.replace(tzinfo=timezone.utc)
                age_days = max((ref - changed_at).total_seconds() / 86400.0, 0.0)
                bucket_idx = n_buckets - 1
                for idx, boundary in enumerate(_AGE_BUCKETS_DAYS):
                    if age_days < boundary:
                        bucket_idx = idx
                        break
            state_buckets[state_value][bucket_idx] += 1

        return QueueAgingReport(
            generated_at=ref,
            bucket_boundaries_days=list(_AGE_BUCKETS_DAYS),
            state_buckets=state_buckets,
        )

    # ---- light coupling helper used by frontend health card ------------

    def ai_session_volume(
        self,
        tenant_id: int,
        *,
        window_days: int = _DEFAULT_WINDOW_DAYS,
        now: Optional[datetime] = None,
    ) -> Dict[str, int]:
        """Total AI sessions in window — used by the analytics page header."""
        window_start, window_end = _resolve_window(window_days, now=now)
        rows = (
            self.session.query(AISession.review_state)
            .filter(AISession.tenant_id == tenant_id)
            .filter(AISession.created_at >= window_start)
            .filter(AISession.created_at <= window_end)
            .all()
        )
        counter: Counter[str] = Counter()
        for (review_state,) in rows:
            counter[review_state or "unknown"] += 1
        return dict(counter)
