"""Route normalized runtime events by severity and source (WS7 event routing)."""

from __future__ import annotations

from typing import Any

_KNOWN_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "notice",
    "warning",
    "info",
    "error",
)


def route_events_by_severity(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Partition events into severity buckets (empty buckets omitted)."""
    buckets: dict[str, list[dict[str, Any]]] = {k: [] for k in _KNOWN_SEVERITIES}
    other: list[dict[str, Any]] = []
    for evt in events:
        if not isinstance(evt, dict):
            continue
        sev = str(evt.get("severity") or "info").lower()
        if sev in buckets:
            buckets[sev].append(evt)
        else:
            other.append(evt)
    out = {k: v for k, v in buckets.items() if v}
    if other:
        out["other"] = other
    return out


def route_events_by_source_tool(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events by envelope ``source_tool``."""
    out: dict[str, list[dict[str, Any]]] = {}
    for evt in events:
        if not isinstance(evt, dict):
            continue
        tool = str(evt.get("source_tool") or "unknown")
        out.setdefault(tool, []).append(evt)
    return out
