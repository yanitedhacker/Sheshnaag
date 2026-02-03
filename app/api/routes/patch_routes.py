"""Patch optimization API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import require_scope
from app.models.patch import Patch, AssetPatch
from app.models.ops import PatchPlan, PatchPlanItem
from app.patch_optimizer.engine import PatchOptimizer
from app.patch_scheduler.constraints import SchedulingConstraints
from app.patch_scheduler.scheduler import PatchScheduler

router = APIRouter(prefix="/api/patches", tags=["Patches"])


class PatchDecisionOut(BaseModel):
    patch_id: str
    priority_score: float
    decision: str
    expected_risk_reduction: float
    justification: List[str]
    axes: dict


class PatchScheduleRequest(BaseModel):
    downtime_budget_minutes: int = Field(60, ge=0, le=24 * 60)
    team_capacity: int = Field(5, ge=1, le=100)
    allowed_windows: Optional[List[str]] = None


@router.get("/priorities")
def get_patch_priorities(
    limit: int = Query(50, ge=1, le=200, description="Number of patches to return"),
    delay_days: int = Query(0, ge=0, le=365, description="Simulate delaying patching by N days"),
    session: Session = Depends(get_sync_session),
):
    """
    Get patch-centric ranked list.

    Returns decisions (not just raw scores) with justification.
    """
    optimizer = PatchOptimizer(session)
    decisions = optimizer.compute_decisions(delay_days=delay_days)[:limit]

    patch_ids = [d.patch_id for d in decisions]
    patches = session.query(Patch).filter(Patch.patch_id.in_(patch_ids)).all()
    patch_by_id = {p.patch_id: p for p in patches}

    windows = session.query(AssetPatch).filter(AssetPatch.patch_id.in_(patch_ids)).all()
    window_by_patch: dict[str, str] = {}
    for w in windows:
        if w.patch_id not in window_by_patch and w.maintenance_window:
            window_by_patch[w.patch_id] = w.maintenance_window

    return {
        "count": len(decisions),
        "priorities": [
            {
                "patch_id": d.patch_id,
                "priority_score": d.priority_score,
                "decision": d.decision,
                "expected_risk_reduction": d.expected_risk_reduction,
                "justification": d.justification,
                "estimated_downtime_minutes": (patch_by_id.get(d.patch_id).estimated_downtime_minutes if patch_by_id.get(d.patch_id) else None),
                "requires_reboot": (patch_by_id.get(d.patch_id).requires_reboot if patch_by_id.get(d.patch_id) else None),
                "maintenance_window": window_by_patch.get(d.patch_id),
            }
            for d in decisions
        ],
        "delay_days": delay_days,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/decisions")
def get_patch_decisions(
    delay_days: int = Query(0, ge=0, le=365, description="Simulate delaying patching by N days"),
    session: Session = Depends(get_sync_session),
):
    """Get patch decisions with axes and justification."""
    optimizer = PatchOptimizer(session)
    decisions = optimizer.compute_decisions(delay_days=delay_days)
    return {
        "count": len(decisions),
        "decisions": [
            PatchDecisionOut(
                patch_id=d.patch_id,
                priority_score=d.priority_score,
                decision=d.decision,
                expected_risk_reduction=d.expected_risk_reduction,
                justification=d.justification,
                axes={
                    "EL": d.axes.EL,
                    "IS": d.axes.IS,
                    "ACS": d.axes.ACS,
                    "PCS": d.axes.PCS,
                    "TPM": d.axes.TPM,
                },
            ).model_dump()
            for d in decisions
        ],
        "delay_days": delay_days,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.post("/schedule", dependencies=[Depends(require_scope("admin"))])
def create_patch_schedule(
    request: PatchScheduleRequest,
    session: Session = Depends(get_sync_session),
):
    """
    Propose a schedule for applying patches.

    Initial implementation uses a greedy heuristic.
    """
    constraints = SchedulingConstraints(
        downtime_budget_minutes=request.downtime_budget_minutes,
        team_capacity=request.team_capacity,
        allowed_windows=request.allowed_windows,
    )
    scheduler = PatchScheduler(session)
    schedule = scheduler.propose_schedule(constraints)

    # Persist plan
    plan = PatchPlan(
        name=f"Plan {datetime.utcnow().isoformat()}",
        constraints=schedule.get("constraints", [])[0] if schedule.get("constraints") else {},
        status="proposed",
    )
    session.add(plan)
    session.flush()

    # Flatten items
    order = 0
    for window in schedule.get("schedule", []):
        for patch_id in window.get("patches", []):
            item = PatchPlanItem(
                plan_id=plan.id,
                patch_id=patch_id,
                window=window.get("window"),
                decision="SCHEDULE",
                expected_risk_reduction=window.get("risk_reduction"),
                estimated_downtime_minutes=window.get("total_downtime"),
                sort_order=order,
            )
            session.add(item)
            order += 1

    return {
        **schedule,
        "plan_id": plan.id,
    }


@router.get("/{patch_id}")
def get_patch_detail(
    patch_id: str,
    session: Session = Depends(get_sync_session),
):
    """Get patch detail with linked CVEs and affected assets."""
    patch: Patch | None = session.query(Patch).filter(Patch.patch_id == patch_id).first()
    if not patch:
        raise HTTPException(status_code=404, detail=f"Patch {patch_id} not found")

    # Asset mappings
    mappings = session.query(AssetPatch).filter(AssetPatch.patch_id == patch_id).all()

    return {
        "patch": {
            "patch_id": patch.patch_id,
            "vendor": patch.vendor,
            "affected_software": patch.affected_software,
            "requires_reboot": patch.requires_reboot,
            "estimated_downtime_minutes": patch.estimated_downtime_minutes,
            "rollback_complexity": patch.rollback_complexity,
            "historical_failure_rate": patch.historical_failure_rate,
            "change_risk_score": patch.change_risk_score,
            "reboot_group": patch.reboot_group,
            "released_at": patch.released_at.isoformat() if patch.released_at else None,
            "source": patch.source,
            "advisory_url": patch.advisory_url,
            "vendor_advisory_id": patch.vendor_advisory_id,
        },
        "linked_cves": [
            {
                "cve_id": c.cve_id,
                "cvss_v3_score": c.cvss_v3_score,
                "exploit_available": c.exploit_available,
            }
            for c in (patch.cves or [])
        ],
        "asset_mappings": [
            {
                "asset_id": m.asset_id,
                "patch_id": m.patch_id,
                "maintenance_window": m.maintenance_window,
                "environment": m.environment,
                "status": m.status,
            }
            for m in mappings
        ],
    }
