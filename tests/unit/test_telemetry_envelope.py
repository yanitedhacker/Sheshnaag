"""Runtime telemetry envelope (WS7)."""

import pytest

from app.lab.telemetry_envelope import (
    SCHEMA_VERSION,
    base_event,
    normalize_falco_line,
    validate_runtime_event,
)
from app.lab.telemetry_translation import events_to_findings, translate_with_enterprise_pack


@pytest.mark.unit
def test_validate_runtime_event_requires_fields():
    ok, errs = validate_runtime_event({})
    assert not ok
    assert any("missing_field" in e for e in errs)


@pytest.mark.unit
def test_base_event_validates():
    evt = base_event(source_tool="tracee", severity="high")
    ok, errs = validate_runtime_event(evt)
    assert ok
    assert not errs
    assert evt["schema_version"] == SCHEMA_VERSION


@pytest.mark.unit
def test_normalize_falco_line():
    line = '{"rule":"test","priority":"CRITICAL","output_fields":{"proc.name":"bash"}}'
    evt = normalize_falco_line(line)
    assert evt is not None
    ok, _ = validate_runtime_event(evt)
    assert ok
    assert evt["source_tool"] == "falco"


@pytest.mark.unit
def test_events_to_findings_groups():
    evts = [
        base_event(source_tool="falco", severity="high", policy={"rule": "r1"}),
        base_event(source_tool="falco", severity="high", policy={"rule": "r1"}),
    ]
    findings = events_to_findings(evts)
    assert len(findings) >= 1
    assert findings[0]["event_count"] == 2


@pytest.mark.unit
def test_translate_with_enterprise_pack_runs():
    evts = [
        base_event(
            source_tool="tracee",
            severity="info",
            process={"cmdline": "curl http://evil.example"},
        )
    ]
    out = translate_with_enterprise_pack(evts)
    assert "findings" in out
    assert "events_tagged" in out
