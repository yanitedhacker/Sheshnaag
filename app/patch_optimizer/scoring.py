"""Score components for patch prioritization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.patch_optimizer.time_models import time_pressure_multiplier


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def criticality_score(criticality: Optional[str]) -> float:
    """
    Map asset criticality string to normalized score in [0,1].

    Defaults to medium if unknown.
    """
    c = (criticality or "medium").strip().lower()
    if c == "critical":
        return 1.0
    if c == "high":
        return 0.8
    if c == "medium":
        return 0.5
    if c == "low":
        return 0.2
    return 0.5


def environment_score(environment: Optional[str]) -> float:
    """
    Map environment to normalized exposure/importance score.
    """
    e = (environment or "production").strip().lower()
    if e == "production":
        return 1.0
    if e == "staging":
        return 0.7
    if e == "development":
        return 0.4
    return 0.7


def exploit_likelihood_score(exploit_probability: Optional[float]) -> float:
    return _clamp01(float(exploit_probability or 0.0))


def impact_score_from_cvss(cvss_v3_score: Optional[float]) -> float:
    """
    Normalize CVSS (0-10) into [0,1].
    """
    if cvss_v3_score is None:
        return 0.0
    return _clamp01(float(cvss_v3_score) / 10.0)


def patch_cost_score(
    *,
    requires_reboot: bool,
    estimated_downtime_minutes: int,
    rollback_complexity: float,
    historical_failure_rate: float,
    change_risk_score: float,
) -> float:
    """
    Compute patch cost score (PCS) in [0,1], where higher means costlier.

    PCS is used in denominator of the guide's formula; downstream code should
    clamp to epsilon before division.
    """
    reboot = 1.0 if requires_reboot else 0.0
    downtime = max(0.0, float(estimated_downtime_minutes)) / 120.0  # 2h baseline
    downtime = _clamp01(downtime)
    rollback = _clamp01(float(rollback_complexity or 0.0))
    fail = _clamp01(float(historical_failure_rate or 0.0))
    change_risk = _clamp01(float(change_risk_score or 0.0))

    pcs = (
        0.25
        + 0.25 * reboot
        + 0.25 * downtime
        + 0.15 * rollback
        + 0.07 * fail
        + 0.03 * change_risk
    )
    return _clamp01(pcs)


def time_pressure_score(
    *,
    cve_published_at: Optional[datetime],
    patch_released_at: Optional[datetime],
    as_of: Optional[datetime] = None,
    delay_days: float = 0.0,
) -> float:
    """
    Compute TPM in [0,1] from time since patch/CVE became relevant.

    We prefer CVE published date if available; otherwise patch released date.
    """
    now = as_of or datetime.utcnow()
    base = cve_published_at or patch_released_at
    if not base:
        return 0.0
    days = (now - base).total_seconds() / 86400.0 + max(0.0, float(delay_days))
    return time_pressure_multiplier(days)


@dataclass(frozen=True)
class PatchAxisScores:
    EL: float
    IS: float
    ACS: float
    PCS: float
    TPM: float
