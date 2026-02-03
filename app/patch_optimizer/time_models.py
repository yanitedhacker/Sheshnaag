"""Time pressure models for patch urgency."""

from __future__ import annotations

import math


def time_pressure_multiplier(days: float) -> float:
    """
    Non-linear urgency growth over time.

    Returns a value in [0, 1]. It starts low and approaches 1 as days increase.
    """
    d = max(0.0, float(days))

    # Logistic curve with midpoint around 14 days.
    # This makes urgency ramp meaningfully after ~1-2 weeks.
    k = 0.22
    x0 = 14.0
    val = 1.0 / (1.0 + math.exp(-k * (d - x0)))

    # Clamp for numerical safety
    if val < 0.0:
        return 0.0
    if val > 1.0:
        return 1.0
    return val

