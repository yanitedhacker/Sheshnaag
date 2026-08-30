"""V6 W2 — libvirt provider plan and collectors."""

from __future__ import annotations

from types import SimpleNamespace

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


@pytest.mark.unit
def test_libvirt_execute_fails_closed_when_virsh_is_missing(monkeypatch):
    provider = LibvirtWindowsProvider()
    monkeypatch.setattr(provider, "_virsh_available", lambda: False)

    result = provider.launch(
        revision_content={"vm": {"domain": "win-proof"}},
        run_context={"launch_mode": "execute"},
    )

    assert result.state.value == "errored"
    assert result.health.value == "errored"
    assert "virsh" in (result.error or "")


@pytest.mark.unit
def test_libvirt_execute_does_not_report_running_when_domain_check_fails(
    monkeypatch,
):
    provider = LibvirtWindowsProvider()
    monkeypatch.setattr(provider, "_virsh_available", lambda: True)
    monkeypatch.setattr(
        "app.lab.providers.libvirt_provider.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="domain not found",
        ),
    )

    result = provider.launch(
        revision_content={"vm": {"domain": "win-proof"}},
        run_context={"launch_mode": "execute"},
    )

    assert result.state.value == "errored"
    assert result.health.value == "errored"
    assert "domain not found" in (result.error or "")


@pytest.mark.unit
def test_libvirt_execute_uses_one_configured_domain(monkeypatch):
    provider = LibvirtWindowsProvider()
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        if "domstate" in argv:
            return SimpleNamespace(returncode=0, stdout="shut off\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(provider, "_virsh_available", lambda: True)
    monkeypatch.setattr("app.lab.providers.libvirt_provider.subprocess.run", fake_run)

    result = provider.launch(
        revision_content={"vm": {"domain": "win-proof"}},
        run_context={"launch_mode": "execute"},
    )

    assert result.state.value == "running"
    assert result.provider_run_ref == "win-proof"
    assert calls
    assert all("win-proof" in argv for argv in calls)
    assert not any("snapshot-create-as" in argv for argv in calls)
