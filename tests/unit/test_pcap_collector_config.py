"""Verify the V4 profile-driven PCAP collector configuration.

The old v2 cap of 5 s / 20 packets / 64 KB is gone. These tests lock in the
new generous defaults and the ``pcap_enabled`` gating semantics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from app.lab.collector_contract import build_provider_result_dict
from app.lab.collectors import pcap as pcap_module
from app.lab.collectors.pcap import (
    DEFAULT_DURATION_SECONDS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_PACKETS,
    PcapCollector,
    resolve_pcap_config,
)


def _run_collector(
    monkeypatch,
    *,
    plan_overrides: Dict[str, Any],
    enable_env: bool = True,
    returned_out: str = "c2hlc2huYWFnLXBjYXAtcHJldmlldw==",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    collector = PcapCollector()

    captured: Dict[str, Any] = {}

    def fake_run_in_guest(provider_result, argv, timeout_sec=90, stdin_text=None):
        captured["argv"] = list(argv)
        captured["timeout_sec"] = timeout_sec
        return 0, returned_out, ""

    monkeypatch.setattr(pcap_module, "run_in_guest", fake_run_in_guest)
    monkeypatch.setattr(
        pcap_module,
        "env_flag_enabled",
        lambda name, default=False: enable_env,
    )

    plan: Dict[str, Any] = {"provider": "lima", "instance_name": "sheshnaag-lima-1"}
    plan.update(plan_overrides)

    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="lima-1",
            plan=plan,
            state="running",
        ),
    )
    return captured, evidence


@pytest.mark.unit
def test_resolve_pcap_config_defaults_are_generous_not_restrictive():
    resolved = resolve_pcap_config({})
    assert resolved["pcap_enabled"] is True
    assert resolved["duration_seconds"] == DEFAULT_DURATION_SECONDS == 30
    assert resolved["max_packets"] == DEFAULT_MAX_PACKETS == 10000
    assert resolved["max_bytes"] == DEFAULT_MAX_BYTES == 10 * 1024 * 1024
    assert resolved["source"] == "defaults"


@pytest.mark.unit
def test_resolve_pcap_config_reads_collector_config_key():
    plan = {
        "collector_config": {
            "pcap": {
                "duration_seconds": 90,
                "max_packets": 500,
                "max_bytes": 2_000_000,
            }
        }
    }
    resolved = resolve_pcap_config(plan)
    assert resolved["duration_seconds"] == 90
    assert resolved["max_packets"] == 500
    assert resolved["max_bytes"] == 2_000_000
    assert resolved["source"] == "collector_config"


@pytest.mark.unit
def test_resolve_pcap_config_zero_means_unlimited():
    plan = {"collector_config": {"pcap": {"max_packets": 0, "max_bytes": 0}}}
    resolved = resolve_pcap_config(plan)
    assert resolved["max_packets"] == 0
    assert resolved["max_bytes"] == 0


@pytest.mark.unit
def test_collector_uses_generous_defaults_not_old_5s_cap(monkeypatch):
    captured, evidence = _run_collector(monkeypatch, plan_overrides={})
    argv = captured["argv"]
    joined = " ".join(argv)
    # The removed v2 cap would have emitted "timeout 5" and "-c 20".
    assert "timeout 5 " not in joined
    assert " -c 20 " not in joined
    # And the new defaults should appear.
    assert f"timeout {DEFAULT_DURATION_SECONDS}" in joined
    assert f"-c {DEFAULT_MAX_PACKETS}" in joined
    assert f"head -c {DEFAULT_MAX_BYTES}" in joined

    payload = evidence[0]["payload"]
    cfg = payload["capture_config"]
    assert cfg["duration_seconds"] == DEFAULT_DURATION_SECONDS
    assert cfg["max_packets"] == DEFAULT_MAX_PACKETS
    assert cfg["max_bytes"] == DEFAULT_MAX_BYTES
    assert cfg["source"] == "defaults"
    assert cfg["pcap_enabled"] is True


@pytest.mark.unit
def test_collector_honors_profile_overrides(monkeypatch):
    overrides = {
        "collector_config": {
            "pcap": {
                "duration_seconds": 60,
                "max_packets": 1234,
                "max_bytes": 555_000,
            }
        }
    }
    captured, evidence = _run_collector(monkeypatch, plan_overrides=overrides)
    joined = " ".join(captured["argv"])
    assert "timeout 60" in joined
    assert "-c 1234" in joined
    assert "head -c 555000" in joined

    cfg = evidence[0]["payload"]["capture_config"]
    assert cfg["duration_seconds"] == 60
    assert cfg["max_packets"] == 1234
    assert cfg["max_bytes"] == 555_000
    assert cfg["source"] == "collector_config"


@pytest.mark.unit
def test_collector_unlimited_packets_and_bytes_omits_flags(monkeypatch):
    overrides = {
        "collector_config": {
            "pcap": {
                "duration_seconds": 45,
                "max_packets": 0,
                "max_bytes": 0,
            }
        }
    }
    captured, evidence = _run_collector(monkeypatch, plan_overrides=overrides)
    joined = " ".join(captured["argv"])
    assert "timeout 45" in joined
    # Zero = unlimited => no -c flag and no byte-head pipeline.
    assert " -c " not in joined
    assert "head -c" not in joined

    cfg = evidence[0]["payload"]["capture_config"]
    assert cfg["max_packets"] == 0
    assert cfg["max_bytes"] == 0


@pytest.mark.unit
def test_pcap_enabled_flag_false_skips_capture(monkeypatch):
    overrides = {"collector_config": {"pcap": {"pcap_enabled": False}}}

    collector = PcapCollector()

    def fake_run_in_guest(*args, **kwargs):
        raise AssertionError("run_in_guest must not be called when pcap_enabled=False")

    monkeypatch.setattr(pcap_module, "run_in_guest", fake_run_in_guest)
    monkeypatch.setattr(pcap_module, "env_flag_enabled", lambda name, default=False: True)

    evidence = collector.collect(
        run_context={"run_id": 1, "launch_mode": "execute"},
        provider_result=build_provider_result_dict(
            provider_run_ref="lima-1",
            plan={
                "provider": "lima",
                "instance_name": "sheshnaag-lima-1",
                **overrides,
            },
            state="running",
        ),
    )
    payload = evidence[0]["payload"]
    assert payload["mode"] == "disabled"
    assert payload["reason"] == "profile_flag_off"
    assert payload["collector_health"]["skip_reason"] == "pcap_enabled_false"


@pytest.mark.unit
def test_pcap_enabled_default_true_runs(monkeypatch):
    captured, evidence = _run_collector(monkeypatch, plan_overrides={})
    payload = evidence[0]["payload"]
    assert payload["mode"] == "live"
    assert payload["capture_config"]["pcap_enabled"] is True
    assert "argv" in captured
