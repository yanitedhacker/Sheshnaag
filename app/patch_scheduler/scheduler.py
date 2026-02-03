"""Greedy patch scheduler (initial implementation)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.patch import AssetPatch, Patch
from app.models.ops import PatchDependency
from app.patch_optimizer.engine import PatchDecisionResult, PatchOptimizer
from app.patch_scheduler.constraints import SchedulingConstraints


@dataclass(frozen=True)
class ScheduledWindow:
    window: str
    patches: List[str]
    total_downtime: int
    risk_reduction: float


class PatchScheduler:
    """
    Greedy heuristic that maximizes risk reduction per downtime minute.

    Batching rules (initial):
    - Schedule by (maintenance_window) inferred from AssetPatch rows.
    - Optionally filter by allowed_windows.
    """

    def __init__(self, session: Session):
        self.session = session
        self.optimizer = PatchOptimizer(session)

    def propose_schedule(self, constraints: SchedulingConstraints) -> Dict[str, List[dict]]:
        decisions = self.optimizer.compute_decisions()

        # Build patch -> downtime and patch -> suggested window set
        patch_windows: Dict[str, Optional[str]] = {}
        patch_downtime: Dict[str, int] = {}
        patch_reboot_group: Dict[str, Optional[str]] = {}
        for ap in self.session.query(AssetPatch).all():
            if ap.patch_id not in patch_windows and ap.maintenance_window:
                patch_windows[ap.patch_id] = ap.maintenance_window
            # if multiple windows exist we keep first (best-effort)

        # pull downtime from Patch rows via optimizer list
        for p in self.optimizer.list_patches():
            patch_downtime[p.patch_id] = int(p.estimated_downtime_minutes or 0)
            patch_reboot_group[p.patch_id] = p.reboot_group

        # Candidate patches: prioritize PATCH_NOW + SCHEDULE
        candidates = [d for d in decisions if d.decision in ("PATCH_NOW", "SCHEDULE")]

        # Group by window
        buckets: Dict[str, List[PatchDecisionResult]] = {}
        for d in candidates:
            w = patch_windows.get(d.patch_id) or "UNASSIGNED"
            if constraints.allowed_windows and w not in constraints.allowed_windows:
                continue
            buckets.setdefault(w, []).append(d)

        dependencies = self._load_dependencies()
        scheduled: List[ScheduledWindow] = []
        for window, items in buckets.items():
            selected, total_dt, total_rr = self._solve_window(
                items=items,
                patch_downtime=patch_downtime,
                patch_reboot_group=patch_reboot_group,
                dependencies=dependencies,
                constraints=constraints,
            )

            scheduled.append(
                ScheduledWindow(
                    window=window,
                    patches=selected,
                    total_downtime=total_dt,
                    risk_reduction=min(1.0, total_rr),
                )
            )

        # Return stable ordering: assigned windows first, unassigned last
        scheduled.sort(key=lambda w: (w.window == "UNASSIGNED", w.window))

        return {
            "constraints": [asdict(constraints)],
            "schedule": [asdict(w) for w in scheduled],
        }

    def _load_dependencies(self) -> List[PatchDependency]:
        return self.session.query(PatchDependency).all()

    def _solve_window(
        self,
        *,
        items: List[PatchDecisionResult],
        patch_downtime: Dict[str, int],
        patch_reboot_group: Dict[str, Optional[str]],
        dependencies: List[PatchDependency],
        constraints: SchedulingConstraints,
    ) -> Tuple[List[str], int, float]:
        """
        Optimize patch selection using OR-Tools if available; fallback to greedy.
        """
        try:
            from ortools.linear_solver import pywraplp
        except Exception:
            return self._greedy_select(items, patch_downtime, constraints)

        solver = pywraplp.Solver.CreateSolver("CBC")
        if solver is None:
            return self._greedy_select(items, patch_downtime, constraints)

        # Decision variables
        patch_ids = [i.patch_id for i in items]
        x = {pid: solver.BoolVar(pid) for pid in patch_ids}

        # Objective: maximize total expected risk reduction
        solver.Maximize(solver.Sum(x[pid] * float(next(i.expected_risk_reduction for i in items if i.patch_id == pid)) for pid in patch_ids))

        # Downtime budget
        solver.Add(
            solver.Sum(x[pid] * int(patch_downtime.get(pid, 0)) for pid in patch_ids)
            <= constraints.downtime_budget_minutes
        )

        # Team capacity
        solver.Add(solver.Sum(x[pid] for pid in patch_ids) <= constraints.team_capacity)

        # Dependency constraints
        for dep in dependencies:
            if dep.patch_id in x and dep.depends_on_patch_id in x:
                if dep.kind == "requires":
                    solver.Add(x[dep.patch_id] <= x[dep.depends_on_patch_id])
                elif dep.kind == "conflicts":
                    solver.Add(x[dep.patch_id] + x[dep.depends_on_patch_id] <= 1)

        # Reboot group constraint: avoid more than 1 per group per window
        group_map: Dict[str, List[str]] = {}
        for pid in patch_ids:
            group = patch_reboot_group.get(pid)
            if group:
                group_map.setdefault(group, []).append(pid)
        for group, pids in group_map.items():
            solver.Add(solver.Sum(x[pid] for pid in pids) <= 1)

        status = solver.Solve()
        if status != pywraplp.Solver.OPTIMAL:
            return self._greedy_select(items, patch_downtime, constraints)

        selected: List[str] = []
        total_dt = 0
        total_rr = 0.0
        for item in items:
            if x[item.patch_id].solution_value() > 0.5:
                selected.append(item.patch_id)
                total_dt += int(patch_downtime.get(item.patch_id, 0))
                total_rr += float(item.expected_risk_reduction)

        return selected, total_dt, min(1.0, total_rr)

    def _greedy_select(
        self,
        items: List[PatchDecisionResult],
        patch_downtime: Dict[str, int],
        constraints: SchedulingConstraints,
    ) -> Tuple[List[str], int, float]:
        # Greedy by risk_reduction per downtime
        def ratio(x: PatchDecisionResult) -> float:
            dt = max(1, patch_downtime.get(x.patch_id, 1))
            return float(x.expected_risk_reduction) / float(dt)

        items_sorted = sorted(items, key=ratio, reverse=True)

        total_dt = 0
        total_rr = 0.0
        selected: List[str] = []

        for item in items_sorted:
            if len(selected) >= constraints.team_capacity:
                break

            dt = int(patch_downtime.get(item.patch_id, 0))
            if total_dt + dt > constraints.downtime_budget_minutes:
                continue

            selected.append(item.patch_id)
            total_dt += dt
            total_rr += float(item.expected_risk_reduction)

        return selected, total_dt, min(1.0, total_rr)
