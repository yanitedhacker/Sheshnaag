"""Scheduling constraints for patch application windows."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SchedulingConstraints:
    downtime_budget_minutes: int = 60
    team_capacity: int = 5  # max patches per window
    allowed_windows: list[str] | None = None  # if set, only schedule within these windows
