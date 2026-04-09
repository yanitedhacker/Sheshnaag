"""WS7 event routing helpers."""

import pytest

from app.lab.telemetry_envelope import base_event
from app.lab.telemetry_routing import route_events_by_severity, route_events_by_source_tool
from app.lab.telemetry_slices import build_telemetry_slices


@pytest.mark.unit
def test_route_events_by_severity_buckets():
    ev = [
        base_event(source_tool="falco", severity="high"),
        base_event(source_tool="tracee", severity="info"),
        base_event(source_tool="tracee", severity="critical"),
    ]
    buckets = route_events_by_severity(ev)
    assert "critical" in buckets
    assert "high" in buckets
    assert "info" in buckets


@pytest.mark.unit
def test_route_events_by_source_tool():
    ev = [
        base_event(source_tool="falco", severity="notice"),
        base_event(source_tool="tracee", severity="info"),
    ]
    by_tool = route_events_by_source_tool(ev)
    assert set(by_tool.keys()) == {"falco", "tracee"}
    assert len(by_tool["falco"]) == 1


@pytest.mark.unit
def test_build_telemetry_slices_adds_summary_routes_and_overhead():
    events = [
        base_event(source_tool="falco", severity="high", process={"name": "bash"}, network={"dst_ip": "1.2.3.4"}),
        base_event(source_tool="tracee", severity="info", file_ref={"path": "/tmp/demo"}),
    ]
    payload = build_telemetry_slices(
        collector_name="tracee_events",
        normalized_events=events,
        findings=[{"title": "Runtime cluster", "severity": "high"}],
        collector_health={"duration_ms": 10, "output_bytes": 50, "status": "ok"},
    )
    assert payload["telemetry_summary"]["event_count"] == 2
    assert payload["telemetry_summary"]["source_tools"]["falco"] == 1
    assert payload["telemetry_routes"]["by_severity"]["high"]
    assert payload["collector_overhead"]["duration_ms"] == 10
