from __future__ import annotations

import subprocess

import pytest

from app.lab.interfaces import RunState
from app.lab.lima_provider import LimaProvider


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.mark.unit
def test_lima_execute_boot_records_secure_mode_audit(monkeypatch, tmp_path):
    provider = LimaProvider()
    monkeypatch.setattr("app.lab.lima_provider.shutil.which", lambda name: "/usr/bin/limactl")
    monkeypatch.setattr(provider, "_workspace_for_ref", lambda provider_run_ref: tmp_path / provider_run_ref)
    monkeypatch.setattr(provider, "_limactl_version", lambda: "limactl version 1.2.3")
    monkeypatch.setattr(
        "app.lab.lima_provider.subprocess.run",
        lambda *args, **kwargs: _Completed(returncode=0, stdout="started", stderr=""),
    )

    responses = [
        (0, "ready\n", ""),
        (0, "secure-run\n", ""),
    ]

    def fake_guest_shell(instance_name: str, command: str, *, timeout: int = 120):
        return responses.pop(0)

    monkeypatch.setattr(provider, "_guest_shell", fake_guest_shell)

    plan = provider.build_plan(
        revision_content={
            "provider": "lima",
            "image_profile": "secure_lima",
            "command": ["bash", "-lc", "echo secure-run"],
            "vm": {"cpu": 2, "memory_mb": 2048, "disk_gb": 10},
        },
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1},
    )
    created = provider.create(plan=plan, run_context={"launch_mode": "execute"})
    result = provider.boot(provider_run_ref=created.provider_run_ref)

    assert result.state == RunState.RUNNING
    assert result.plan["execute_result"]["exit_code"] == 0
    assert result.plan["secure_mode_audit"]["execute_result"]["command_text"] == "bash -lc 'echo secure-run'"
    lifecycle = result.plan["secure_mode_audit"]["lifecycle"]
    assert any(item["event"] == "booted" for item in lifecycle)
    assert any(item["event"] == "executed" for item in lifecycle)
    assert result.plan["guest_instance"]["instance_name"].startswith("sheshnaag-")


@pytest.mark.unit
def test_lima_launch_blocks_without_limactl(monkeypatch):
    provider = LimaProvider()
    monkeypatch.setattr("app.lab.lima_provider.shutil.which", lambda name: None)
    result = provider.launch(
        revision_content={"provider": "lima", "image_profile": "secure_lima"},
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1, "launch_mode": "execute"},
    )
    assert result.state == RunState.BLOCKED
    assert result.error == "provider_not_ready"


@pytest.mark.unit
def test_lima_capabilities_are_guest_tool_aware(monkeypatch):
    monkeypatch.delenv("SHESHNAAG_ENABLE_PCAP", raising=False)
    provider = LimaProvider()
    plan = provider.build_plan(
        revision_content={
            "provider": "lima",
            "image_profile": "secure_lima",
            "collectors": ["process_tree", "file_diff", "network_metadata", "pcap", "tracee_events"],
        },
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1},
    )

    capabilities = {item["collector_name"]: item for item in plan["collector_capabilities"]}
    assert plan["secure_mode_contract"]["snapshot_revert_supported"] is False
    assert capabilities["process_tree"]["status"] == "ready"
    assert capabilities["process_tree"]["execution"] == "lima_shell"
    assert "procps" in capabilities["process_tree"]["required_guest_tools"]
    assert capabilities["network_metadata"]["required_guest_tools"] == ["iproute2", "net-tools"]
    assert capabilities["pcap"]["status"] == "degraded"
    assert "tcpdump" in capabilities["pcap"]["required_guest_tools"]
    assert capabilities["tracee_events"]["status"] == "degraded"


@pytest.mark.unit
def test_lima_teardown_records_ephemeral_destroy_not_disk_revert(monkeypatch, tmp_path):
    provider = LimaProvider()
    monkeypatch.setattr("app.lab.lima_provider.shutil.which", lambda name: "/usr/bin/limactl")
    monkeypatch.setattr(provider, "_workspace_for_ref", lambda provider_run_ref: tmp_path / provider_run_ref)
    monkeypatch.setattr(provider, "_limactl_version", lambda: "limactl version 1.2.3")

    plan = provider.build_plan(
        revision_content={"provider": "lima", "image_profile": "secure_lima"},
        run_context={"tenant_slug": "demo", "analyst_name": "Tester", "run_id": 1},
    )
    created = provider.create(plan=plan, run_context={"launch_mode": "execute"})
    result = provider.destroy(provider_run_ref=created.provider_run_ref)

    audit = result.plan["secure_mode_audit"]["snapshot_revert_audit"]
    assert result.state == RunState.DESTROYED
    assert result.plan["teardown"]["restore_action"] == "destroy_ephemeral_instance"
    assert audit["revert_outcome"] == "not_applicable_ephemeral_instance"
    assert audit["reverted_at"] is None
    assert "ephemeral instance destruction" in result.transcript
