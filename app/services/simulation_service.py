"""Scenario simulation for tenant workbench risk and patch capacity."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from sqlalchemy.orm import Session

from app.models.v2 import SimulationRun, Tenant
from app.patch_scheduler.constraints import SchedulingConstraints
from app.patch_scheduler.scheduler import PatchScheduler
from app.services.workbench_service import WorkbenchService


class SimulationService:
    """Run and persist tenant what-if simulations."""

    def __init__(self, session: Session):
        self.session = session
        self.workbench = WorkbenchService(session)
        self.scheduler = PatchScheduler(session)

    def run_risk_simulation(self, tenant: Tenant, *, parameters: dict, persist: bool = True) -> Dict[str, object]:
        """Compute before/after rankings for a given scenario."""
        before = self.workbench.get_summary(tenant, limit=25)
        constraints = SchedulingConstraints(
            downtime_budget_minutes=int(parameters.get("downtime_budget_minutes", 60)),
            team_capacity=int(parameters.get("team_capacity", 3)),
            allowed_windows=parameters.get("allowed_windows"),
        )
        schedule = self.scheduler.propose_schedule(constraints)
        selected_patch_ids = {
            patch_id
            for window in schedule.get("schedule", [])
            for patch_id in window.get("patches", [])
        }

        after = self.workbench.get_summary(tenant, limit=25, scenario=parameters)
        after_actions = []
        total_reduction = 0.0
        for action in after["actions"]:
            is_selected = action["entity_refs"][0]["id"] in selected_patch_ids
            reduction_multiplier = 0.0
            if is_selected:
                reduction_multiplier = min(0.92, 0.45 + float(action["expected_risk_reduction"]))
            elif parameters.get("compensating_controls"):
                reduction_multiplier = 0.12

            post_score = round(action["actionable_risk_score"] * (1.0 - reduction_multiplier), 2)
            total_reduction += max(0.0, action["actionable_risk_score"] - post_score)
            after_actions.append(
                {
                    **action,
                    "selected_for_window": is_selected,
                    "post_simulation_risk_score": post_score,
                }
            )

        after_actions.sort(key=lambda item: item["post_simulation_risk_score"], reverse=True)
        summary = {
            "selected_patch_ids": sorted(selected_patch_ids),
            "windows_considered": len(schedule.get("schedule", [])),
            "actions_selected": len(selected_patch_ids),
            "expected_risk_reduction": round(total_reduction, 2),
            "parameters": parameters,
        }

        run = None
        if persist:
            run = SimulationRun(
                tenant_id=tenant.id,
                name=parameters.get("name") or f"Simulation {datetime.utcnow().isoformat()}",
                parameters=parameters,
                before_snapshot=before,
                after_snapshot={"actions": after_actions},
                summary=summary,
            )
            self.session.add(run)
            self.session.flush()

        return {
            "simulation_id": run.id if run is not None else None,
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "before": before,
            "after": {"actions": after_actions},
            "schedule": schedule,
            "summary": summary,
            "created_at": run.created_at.isoformat() if run is not None and run.created_at else datetime.utcnow().isoformat(),
        }
