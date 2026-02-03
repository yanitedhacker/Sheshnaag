from types import SimpleNamespace

import pytest

from app.patch_scheduler.constraints import SchedulingConstraints
from app.patch_scheduler.scheduler import PatchScheduler


class _FakeQuery:
    def __init__(self, items):
        self._items = items

    def all(self):
        return list(self._items)


class _FakeSession:
    def __init__(self, asset_patches):
        self._asset_patches = asset_patches

    def query(self, model):
        # Only used for AssetPatch in scheduler.
        return _FakeQuery(self._asset_patches)


@pytest.mark.unit
def test_scheduler_respects_budget_and_capacity(monkeypatch):
    # Two patches in same window; choose based on rr/downtime.
    fake_asset_patches = [
        SimpleNamespace(patch_id="P1", maintenance_window="01:00–03:00"),
        SimpleNamespace(patch_id="P2", maintenance_window="01:00–03:00"),
    ]

    session = _FakeSession(fake_asset_patches)
    scheduler = PatchScheduler(session)

    # Patch list with downtimes
    monkeypatch.setattr(
        scheduler.optimizer,
        "list_patches",
        lambda: [
            SimpleNamespace(patch_id="P1", estimated_downtime_minutes=30, reboot_group=None),
            SimpleNamespace(patch_id="P2", estimated_downtime_minutes=10, reboot_group=None),
        ],
    )

    # Decisions with different risk reductions
    monkeypatch.setattr(
        scheduler.optimizer,
        "compute_decisions",
        lambda: [
            SimpleNamespace(patch_id="P1", decision="SCHEDULE", expected_risk_reduction=0.3),
            SimpleNamespace(patch_id="P2", decision="SCHEDULE", expected_risk_reduction=0.2),
        ],
    )

    out = scheduler.propose_schedule(SchedulingConstraints(downtime_budget_minutes=15, team_capacity=1))
    schedule = out["schedule"]
    # Only one window bucket
    assert len(schedule) == 1
    assert schedule[0]["window"] == "01:00–03:00"
    # With 15 min budget and team_capacity 1, only P2 can fit
    assert schedule[0]["patches"] == ["P2"]

