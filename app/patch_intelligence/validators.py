"""Validation helpers for patch metadata inputs."""

from __future__ import annotations


def clamp01(value: float) -> float:
    try:
        v = float(value)
    except Exception:
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def validate_non_negative_int(value: int) -> int:
    v = int(value)
    if v < 0:
        raise ValueError("Value must be non-negative")
    return v

