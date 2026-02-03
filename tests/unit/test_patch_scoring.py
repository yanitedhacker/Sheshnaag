import math

import pytest

from app.patch_optimizer.scoring import (
    criticality_score,
    environment_score,
    patch_cost_score,
)
from app.patch_optimizer.time_models import time_pressure_multiplier


@pytest.mark.unit
def test_time_pressure_multiplier_bounds_and_monotonic():
    vals = [time_pressure_multiplier(d) for d in [0, 1, 7, 14, 30, 90]]
    assert all(0.0 <= v <= 1.0 for v in vals)
    # monotonic non-decreasing
    assert all(a <= b for a, b in zip(vals, vals[1:]))


@pytest.mark.unit
def test_criticality_score_mapping():
    assert criticality_score("critical") == 1.0
    assert criticality_score("high") > criticality_score("medium") > criticality_score("low")
    assert math.isclose(criticality_score(None), 0.5)


@pytest.mark.unit
def test_environment_score_mapping():
    assert environment_score("production") == 1.0
    assert environment_score("staging") < environment_score("production")
    assert environment_score("development") < environment_score("staging")


@pytest.mark.unit
def test_patch_cost_score_behaves_reasonably():
    low = patch_cost_score(
        requires_reboot=False,
        estimated_downtime_minutes=5,
        rollback_complexity=0.1,
        historical_failure_rate=0.01,
    )
    high = patch_cost_score(
        requires_reboot=True,
        estimated_downtime_minutes=120,
        rollback_complexity=0.9,
        historical_failure_rate=0.2,
    )
    assert 0.0 <= low <= 1.0
    assert 0.0 <= high <= 1.0
    assert high > low

