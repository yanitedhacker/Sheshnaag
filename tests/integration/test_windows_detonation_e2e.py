"""V6 W2 — Windows detonation E2E parity harness (requires KVM host)."""

from __future__ import annotations

import pytest

from app.lab.providers.libvirt_provider import LibvirtWindowsProvider


@pytest.mark.kvm
@pytest.mark.integration
def test_windows_detonation_simulated_parity():
    """Evidence parity checklist against Linux Docker baseline (simulated mode)."""
    provider = LibvirtWindowsProvider()
    result = provider.launch(
        revision_content={"collectors": ["sysmon_events", "etw_events", "process_tree"]},
        run_context={"launch_mode": "simulated"},
    )
    plan = result.plan
    assert plan["provider"] == "libvirt"
    assert plan["telemetry"]["sysmon"] is True
    assert plan["telemetry"]["etw"] is True
    assert result.state.value in {"ready", "running", "booting"}
