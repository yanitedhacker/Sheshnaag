"""Patch optimization engine: compute patch priorities and decisions."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.cve import CVE
from app.models.patch import AssetPatch, Patch
from app.models.risk_score import RiskScore
from app.patch_optimizer.scoring import (
    PatchAxisScores,
    criticality_score,
    environment_score,
    exploit_likelihood_score,
    impact_score_from_cvss,
    patch_cost_score,
    time_pressure_score,
)

logger = logging.getLogger(__name__)


Decision = str  # PATCH_NOW | SCHEDULE | DEFER


@dataclass(frozen=True)
class PatchDecisionResult:
    patch_id: str
    priority_score: float
    decision: Decision
    expected_risk_reduction: float
    axes: PatchAxisScores
    justification: List[str]


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _safe_div(n: float, d: float, eps: float = 1e-3) -> float:
    return n / max(eps, d)


class PatchOptimizer:
    """
    Compute patch priorities and decisions using the canonical guide formula:

    PatchPriority = (EL × IS × ACS × TPM) ÷ PCS
    """

    def __init__(self, session: Session):
        self.session = session

    def list_patches(self) -> List[Patch]:
        return self.session.query(Patch).order_by(Patch.vendor, Patch.patch_id).all()

    def compute_decisions(self, *, delay_days: int = 0, as_of: Optional[datetime] = None) -> List[PatchDecisionResult]:
        results: List[PatchDecisionResult] = []
        for patch in self.list_patches():
            try:
                results.append(self.compute_decision_for_patch(patch.patch_id, delay_days=delay_days, as_of=as_of))
            except Exception as e:
                logger.exception("Failed computing patch decision for %s: %s", patch.patch_id, e)

        results.sort(key=lambda r: r.priority_score, reverse=True)
        return results

    def compute_decision_for_patch(self, patch_id: str, *, delay_days: int = 0, as_of: Optional[datetime] = None) -> PatchDecisionResult:
        patch = self.session.query(Patch).filter(Patch.patch_id == patch_id).first()
        if not patch:
            raise ValueError(f"Patch {patch_id} not found")

        cves = list(patch.cves or [])
        assets_with_meta = self._assets_for_patch(patch.patch_id)

        axes, expected_risk_reduction, justification = self._compute_axes(
            patch,
            cves,
            assets_with_meta,
            delay_days=delay_days,
            as_of=as_of,
        )

        numerator = axes.EL * axes.IS * axes.ACS * axes.TPM
        priority_score = _clamp01(_safe_div(numerator, axes.PCS))

        decision = self._decide(priority_score=priority_score, pcs=axes.PCS, assets_with_meta=assets_with_meta)
        justification = self._finalize_justification(decision, axes, assets_with_meta, justification)

        return PatchDecisionResult(
            patch_id=patch.patch_id,
            priority_score=priority_score,
            decision=decision,
            expected_risk_reduction=expected_risk_reduction,
            axes=axes,
            justification=justification,
        )

    def _assets_for_patch(self, patch_id: str) -> List[Tuple[Asset, AssetPatch]]:
        rows = (
            self.session.query(Asset, AssetPatch)
            .join(AssetPatch, AssetPatch.asset_id == Asset.id)
            .filter(AssetPatch.patch_id == patch_id)
            .all()
        )
        return list(rows)

    def _latest_risk_for_cve_ids(self, cve_ids: List[int]) -> Dict[int, RiskScore]:
        """
        Best-effort fetch of latest RiskScore per CVE.

        Note: current schema stores many RiskScore rows per CVE over time.
        """
        if not cve_ids:
            return {}

        # Pull recent scores and keep first per cve_id after sorting by created_at desc.
        scores = (
            self.session.query(RiskScore)
            .filter(RiskScore.cve_id.in_(cve_ids))
            .order_by(desc(RiskScore.created_at))
            .all()
        )
        latest: Dict[int, RiskScore] = {}
        for s in scores:
            if s.cve_id not in latest:
                latest[s.cve_id] = s
        return latest

    def _compute_axes(
        self,
        patch: Patch,
        cves: List[CVE],
        assets_with_meta: List[Tuple[Asset, AssetPatch]],
        *,
        delay_days: int = 0,
        as_of: Optional[datetime] = None,
    ) -> Tuple[PatchAxisScores, float, List[str]]:
        # --- CVE-driven axes ---
        cve_ids = [c.id for c in cves]
        latest_scores = self._latest_risk_for_cve_ids(cve_ids)

        el = 0.0
        iscore = 0.0
        tpm = 0.0
        justification: List[str] = []

        for cve in cves:
            rs = latest_scores.get(cve.id)
            el = max(el, exploit_likelihood_score(rs.exploit_probability if rs else 0.0))
            iscore = max(iscore, impact_score_from_cvss(cve.cvss_v3_score))
            tpm = max(
                tpm,
                time_pressure_score(
                    cve_published_at=cve.published_date,
                    patch_released_at=patch.released_at,
                    delay_days=delay_days,
                    as_of=as_of,
                ),
            )

        if el >= 0.7:
            justification.append("High exploit likelihood across linked CVEs")
        elif el >= 0.4:
            justification.append("Moderate exploit likelihood across linked CVEs")

        if iscore >= 0.9:
            justification.append("Severe impact (high CVSS) on at least one linked CVE")
        elif iscore >= 0.7:
            justification.append("High impact on linked CVEs")

        if tpm >= 0.7:
            justification.append("Rising urgency as vulnerabilities age in the wild")

        # --- Asset-driven axis (ACS) ---
        acs = 0.0
        if assets_with_meta:
            # Use max risk context across affected assets (conservative).
            for asset, mapping in assets_with_meta:
                acs = max(
                    acs,
                    _clamp01(0.65 * criticality_score(asset.criticality) + 0.35 * environment_score(mapping.environment or asset.environment)),
                )
        else:
            # If patch isn't mapped to assets yet, treat as low confidence.
            acs = 0.2
            justification.append("Patch not yet mapped to specific assets (lower confidence)")

        if acs >= 0.85:
            justification.append("Affects high-criticality and/or production assets")
        elif acs >= 0.6:
            justification.append("Affects meaningful assets (criticality/environment)")

        # --- Patch cost axis (PCS) ---
        pcs = patch_cost_score(
            requires_reboot=bool(patch.requires_reboot),
            estimated_downtime_minutes=int(patch.estimated_downtime_minutes or 0),
            rollback_complexity=float(patch.rollback_complexity or 0.0),
            historical_failure_rate=float(patch.historical_failure_rate or 0.0),
            change_risk_score=float(patch.change_risk_score or 0.0),
        )
        if pcs <= 0.35:
            justification.append("Low operational cost to apply")
        elif pcs >= 0.75:
            justification.append("High operational cost to apply")

        # --- Expected risk reduction (heuristic) ---
        expected_risk_reduction = self._expected_risk_reduction(cves, latest_scores, assets_with_meta)

        axes = PatchAxisScores(EL=_clamp01(el), IS=_clamp01(iscore), ACS=_clamp01(acs), PCS=max(0.05, pcs), TPM=_clamp01(tpm))
        return axes, expected_risk_reduction, justification

    def _expected_risk_reduction(
        self,
        cves: List[CVE],
        latest_scores: Dict[int, RiskScore],
        assets_with_meta: List[Tuple[Asset, AssetPatch]],
    ) -> float:
        """
        Heuristic: sum normalized CVE overall scores, weighted by asset criticality/env,
        then squash into [0,1].
        """
        if not cves:
            return 0.0

        # Base per-CVE risk contribution (0..1).
        cve_risk = []
        for cve in cves:
            rs = latest_scores.get(cve.id)
            if rs and rs.overall_score is not None:
                cve_risk.append(_clamp01(float(rs.overall_score) / 100.0))
            else:
                # Fallback: CVSS-only
                cve_risk.append(impact_score_from_cvss(cve.cvss_v3_score))

        base = sum(cve_risk)

        if assets_with_meta:
            # Weight by strongest impacted asset (conservative).
            best_asset_weight = 0.0
            for asset, mapping in assets_with_meta:
                best_asset_weight = max(
                    best_asset_weight,
                    _clamp01(0.7 * criticality_score(asset.criticality) + 0.3 * environment_score(mapping.environment or asset.environment)),
                )
            base *= (0.5 + 0.5 * best_asset_weight)

        # Squash: diminishing returns beyond a couple CVEs
        # 1 - exp(-x) maps x>=0 to [0,1)
        import math

        return _clamp01(1.0 - math.exp(-base / 2.0))

    def _decide(
        self,
        *,
        priority_score: float,
        pcs: float,
        assets_with_meta: List[Tuple[Asset, AssetPatch]],
    ) -> Decision:
        # Hard gates: if no asset mapping, default to schedule (needs triage).
        if not assets_with_meta:
            return "SCHEDULE"

        # Thresholds (tunable); chosen to give sensible behavior with limited data.
        if priority_score >= 0.75 and pcs <= 0.7:
            return "PATCH_NOW"
        if priority_score >= 0.40:
            return "SCHEDULE"
        return "DEFER"

    def _finalize_justification(
        self,
        decision: Decision,
        axes: PatchAxisScores,
        assets_with_meta: List[Tuple[Asset, AssetPatch]],
        existing: List[str],
    ) -> List[str]:
        out = list(dict.fromkeys(existing))  # stable de-dupe

        if decision == "PATCH_NOW":
            out.insert(0, "Recommended to patch immediately")
        elif decision == "SCHEDULE":
            out.insert(0, "Recommended to schedule within the next maintenance window")
        else:
            out.insert(0, "Recommended to defer until conditions change")

        if assets_with_meta:
            # Mention window if consistent across mappings
            windows = {m.maintenance_window for _, m in assets_with_meta if m.maintenance_window}
            if len(windows) == 1:
                w = next(iter(windows))
                out.append(f"Suggested maintenance window: {w}")

        if axes.PCS >= 0.6:
            out.append("Consider staging and rollback plan due to operational cost")

        return out[:8]
