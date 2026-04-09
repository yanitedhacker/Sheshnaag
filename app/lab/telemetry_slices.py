"""Helpers for additive telemetry slices on runtime evidence payloads."""

from __future__ import annotations

from typing import Any, Dict, List

from app.lab.telemetry_routing import route_events_by_severity, route_events_by_source_tool


def build_telemetry_slices(
    *,
    collector_name: str,
    normalized_events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    collector_health: Dict[str, Any],
    raw_preview: str = "",
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    by_severity = route_events_by_severity(normalized_events)
    by_tool = route_events_by_source_tool(normalized_events)
    process_slice = [
        evt.get("process")
        for evt in normalized_events
        if isinstance(evt.get("process"), dict) and evt.get("process")
    ][:100]
    file_slice = [
        evt.get("file")
        for evt in normalized_events
        if isinstance(evt.get("file"), dict) and evt.get("file")
    ][:100]
    network_slice = [
        evt.get("network")
        for evt in normalized_events
        if isinstance(evt.get("network"), dict) and evt.get("network")
    ][:100]
    policy_hits = []
    for evt in normalized_events:
        match = evt.get("policy_match")
        if isinstance(match, dict) and match:
            policy_hits.append(match)
    payload = {
        "collector": collector_name,
        "normalized_events": normalized_events,
        "findings": findings,
        "telemetry_summary": {
            "event_count": len(normalized_events),
            "finding_count": len(findings),
            "source_tools": {tool: len(events) for tool, events in by_tool.items()},
            "severity_counts": {sev: len(events) for sev, events in by_severity.items()},
        },
        "telemetry_routes": {
            "by_severity": {sev: events[:50] for sev, events in by_severity.items()},
            "by_source_tool": {tool: events[:50] for tool, events in by_tool.items()},
        },
        "telemetry_findings": findings[:50],
        "process_slice": process_slice,
        "file_slice": file_slice,
        "network_slice": network_slice,
        "policy_hits": policy_hits[:100],
        "collector_overhead": {
            "duration_ms": collector_health.get("duration_ms"),
            "output_bytes": collector_health.get("output_bytes"),
            "status": collector_health.get("status"),
        },
        "collector_health": collector_health,
    }
    if raw_preview:
        payload["raw_preview"] = raw_preview
    if extra:
        payload.update(extra)
    return payload
