"""V6 W2 — libvirt provider plan and collectors."""

from __future__ import annotations

import pytest

from app.lab.collectors.etw import EtwEventsCollector
from app.lab.collectors.sysmon import SysmonEventsCollector
from app.lab.providers.libvirt_provider import LibvirtWindowsProvider


@pytest.mark.unit
def test_libvirt_build_plan_includes_windows_collectors():
    provider = LibvirtWindowsProvider()
    plan = provider.build_plan(
        revision_content={"collectors": ["sysmon_events", "etw_events"]},
        run_context={"launch_mode": "simulated"},
    )
    assert plan["provider"] == "libvirt"
    assert "sysmon_events" in plan["collectors"]
    assert plan["vm"]["os_family"] == "windows"


@pytest.mark.unit
def test_sysmon_collector_simulated_mode():
    coll = SysmonEventsCollector()
    out = coll.collect(
        run_context={"launch_mode": "simulated"},
        provider_result={"plan": {"synthetic_sysmon": [{"EventID": 1}]}},
    )
    assert out[0]["collector"] == "sysmon_events"


@pytest.mark.unit
def test_etw_collector_simulated_mode():
    coll = EtwEventsCollector()
    out = coll.collect(run_context={"launch_mode": "simulated"}, provider_result={"plan": {}})
    assert out[0]["payload"]["providers"]
