"""WS7 event routing helpers."""

import pytest

from app.lab.telemetry_envelope import base_event
from app.lab.telemetry_routing import route_events_by_severity, route_events_by_source_tool


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
