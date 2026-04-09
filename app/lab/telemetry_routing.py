"""Route normalized runtime events by severity and source (WS7 event routing)."""

from __future__ import annotations

from typing import Any, Dict, List

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


def route_events_by_severity(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Partition events into severity buckets (empty buckets omitted)."""
    buckets: Dict[str, List[Dict[str, Any]]] = {k: [] for k in _KNOWN_SEVERITIES}
    other: List[Dict[str, Any]] = []
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


def route_events_by_source_tool(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group events by envelope ``source_tool``."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for evt in events:
        if not isinstance(evt, dict):
            continue
        tool = str(evt.get("source_tool") or "unknown")
        out.setdefault(tool, []).append(evt)
    return out
