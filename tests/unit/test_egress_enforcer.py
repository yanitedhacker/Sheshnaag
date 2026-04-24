"""Unit tests for ``app.lab.egress_enforcer``.

All tests mock ``shutil.which`` / ``subprocess.*`` so nothing touches the
host kernel.  The enforcer's key property is *dry-run by default*; the
tests exercise both the planning path and the teardown idempotency.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, Iterable, List

import pytest

from app.lab import egress_enforcer as ee_module
from app.lab.egress_enforcer import EgressEnforcer


def _profile(
    *,
    egress_mode: str,
    config: Dict[str, Any] | None = None,
    name: str = "profile-under-test",
    provider_hint: str = "lima",
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        egress_mode=egress_mode,
        provider_hint=provider_hint,
        config=config or {},
    )


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """Force dry-run default and scrub enforcement env vars per-test."""
    monkeypatch.delenv("SHESHNAAG_EGRESS_ENFORCE", raising=False)
    monkeypatch.setattr(
        ee_module.shutil, "which", lambda _name: None, raising=True
    )
    yield


@pytest.mark.unit
def test_default_deny_plan(monkeypatch):
    profile = _profile(egress_mode="default_deny")
    # Explicitly dry-run even if an operator env somehow slipped through.
    enforcer = EgressEnforcer(profile, run_id=42, dry_run=True)

    sentinel_calls: List[Iterable[str]] = []

    def _explode(*args, **kwargs):  # pragma: no cover - would fail the test
        sentinel_calls.append(args)
        raise AssertionError("subprocess.run must not be invoked in dry-run")

    monkeypatch.setattr(ee_module.subprocess, "run", _explode)

    plan = enforcer.apply()

    assert plan["applied"] is False
    assert plan["dry_run"] is True
    assert plan["mode"] == "default_deny"
    assert plan["errors"] == []
    # Exactly one rules blob (nft program) for default_deny.
    assert len(plan["rules"]) == 1
    nft = plan["rules"][0]
    assert "policy drop" in nft
    assert "default_deny" in nft
    assert sentinel_calls == []


@pytest.mark.unit
def test_sinkhole_plan_includes_dns_redirect():
    profile = _profile(
        egress_mode="sinkhole",
        config={"allow_egress_hosts": ["update.example.invalid"]},
    )
    plan = EgressEnforcer(profile, run_id="run-sink", dry_run=True).apply()

    nft_program = plan["rules"][0]
    dnsmasq_conf = plan["rules"][1]
    assert plan["mode"] == "sinkhole"
    assert "udp dport 53 accept" in nft_program
    assert "tcp dport != 53 drop" in nft_program
    assert "address=/#/0.0.0.0" in dnsmasq_conf
    assert "address=/update.example.invalid/127.0.0.1" in dnsmasq_conf


@pytest.mark.unit
def test_fake_internet_plan_references_inetsim():
    profile = _profile(egress_mode="fake_internet")
    plan = EgressEnforcer(profile, run_id=7, dry_run=True).apply()

    assert plan["mode"] == "fake_internet"
    assert len(plan["rules"]) == 2
    nft_program, inetsim_conf = plan["rules"]
    assert "169.254.0.0/16 accept" in nft_program
    assert "start_service dns" in inetsim_conf
    assert "start_service http" in inetsim_conf
    assert "service_bind_address 127.0.0.1" in inetsim_conf


@pytest.mark.unit
def test_missing_binaries_records_errors_not_raises(monkeypatch):
    profile = _profile(egress_mode="default_deny")
    enforcer = EgressEnforcer(profile, run_id=1, dry_run=False)

    # Binaries: all missing.
    monkeypatch.setattr(ee_module.shutil, "which", lambda _name: None)

    # subprocess.run should not even be called because nft is missing; but if
    # something slips through, raising here catches it.
    def _fail(*args, **kwargs):  # pragma: no cover
        raise AssertionError("subprocess.run should not be called when nft missing")

    monkeypatch.setattr(ee_module.subprocess, "run", _fail)

    plan = enforcer.apply()
    assert plan["applied"] is False
    assert plan["dry_run"] is False
    assert plan["errors"], "expected at least one error recorded"
    assert any("nft" in msg for msg in plan["errors"])
    assert plan["binaries"] == {"nft": False, "dnsmasq": False, "inetsim": False}


@pytest.mark.unit
def test_context_manager_tears_down_on_exit(monkeypatch):
    profile = _profile(egress_mode="default_deny")

    teardown_calls: List[str] = []
    original_teardown = EgressEnforcer.teardown

    def _spy(self):  # type: ignore[no-untyped-def]
        teardown_calls.append("called")
        return original_teardown(self)

    monkeypatch.setattr(EgressEnforcer, "teardown", _spy)

    with EgressEnforcer(profile, run_id="ctx", dry_run=True) as enforcer:
        assert enforcer.plan["mode"] == "default_deny"

    assert teardown_calls == ["called"]


@pytest.mark.unit
def test_context_manager_tears_down_on_exception(monkeypatch):
    profile = _profile(egress_mode="default_deny")

    teardown_calls: List[str] = []

    def _spy_teardown(self):  # type: ignore[no-untyped-def]
        teardown_calls.append("called")

    monkeypatch.setattr(EgressEnforcer, "teardown", _spy_teardown)

    with pytest.raises(RuntimeError, match="boom"):
        with EgressEnforcer(profile, run_id="ctx-exc", dry_run=True):
            raise RuntimeError("boom")

    assert teardown_calls == ["called"]


@pytest.mark.unit
def test_allow_list_compiled_to_nft_rules():
    profile = _profile(
        egress_mode="default_deny",
        config={
            "allow_egress_hosts": ["update.example.invalid", "pki.example.invalid"],
            "allow_cidrs": ["10.0.5.0/24", "2001:db8::/32"],
            "allow_ports": [443, 8443],
        },
    )
    plan = EgressEnforcer(profile, run_id=99, dry_run=True).apply()
    nft = plan["rules"][0]

    assert plan["allow_hosts"] == ["update.example.invalid", "pki.example.invalid"]
    assert "ip daddr 10.0.5.0/24 accept" in nft
    assert "ip6 daddr 2001:db8::/32 accept" in nft
    assert "tcp dport 443 accept" in nft
    assert "tcp dport 8443 accept" in nft
    assert "allow-host: update.example.invalid" in nft
    assert "allow-host: pki.example.invalid" in nft


@pytest.mark.unit
def test_none_mode_produces_accept_policy():
    profile = _profile(egress_mode="none")
    plan = EgressEnforcer(profile, run_id="none-mode", dry_run=True).apply()
    nft = plan["rules"][0]
    assert plan["mode"] == "none"
    assert "policy accept" in nft
    assert "drop" not in nft.split("# mode=none")[-1]


@pytest.mark.unit
def test_env_var_flips_dry_run(monkeypatch):
    monkeypatch.setenv("SHESHNAAG_EGRESS_ENFORCE", "1")
    # Binaries absent → still errors out cleanly instead of mutating host.
    monkeypatch.setattr(ee_module.shutil, "which", lambda _name: None)

    profile = _profile(egress_mode="default_deny")
    enforcer = EgressEnforcer(profile, run_id="env")
    assert enforcer.dry_run is False
    plan = enforcer.apply()
    assert plan["dry_run"] is False
    assert plan["applied"] is False
    assert plan["errors"], "expected error stating binaries missing"


@pytest.mark.unit
def test_unknown_mode_falls_back_to_default_deny(caplog):
    profile = _profile(egress_mode="mystery")
    plan = EgressEnforcer(profile, run_id="unk", dry_run=True).apply()
    assert plan["mode"] == "default_deny"
