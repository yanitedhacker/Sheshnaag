"""Unit tests for ``app.lab.snapshot_manager``.

Every test mocks ``shutil.which`` / ``subprocess.run`` so no hypervisor CLI
is touched.  The tests cover each provider's happy path, the always-revert
guarantee (including on exception), and the ``SHESHNAAG_SNAPSHOT_NO_REVERT``
escape hatch.
"""

from __future__ import annotations

import shutil
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from app.lab import snapshot_manager as sm_module
from app.lab.snapshot_manager import SnapshotManager


def _profile(
    *,
    provider_hint: str,
    config: Dict[str, Any] | None = None,
    name: str = "profile-X",
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        provider_hint=provider_hint,
        config=config or {},
    )


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture(autouse=True)
def _scrub_env(monkeypatch):
    monkeypatch.delenv("SHESHNAAG_SNAPSHOT_NO_REVERT", raising=False)
    yield


@pytest.mark.unit
def test_libvirt_snapshot_happy_path(monkeypatch):
    profile = _profile(provider_hint="libvirt", config={"domain": "win10-lab"})

    monkeypatch.setattr(
        sm_module.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "virsh" else None,
    )

    captured_cmds: List[List[str]] = []

    def _fake_run(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        return _Completed(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sm_module.subprocess, "run", _fake_run)

    mgr = SnapshotManager(profile, run_id=1001)
    assert mgr.provider == "libvirt"
    with mgr.with_snapshot() as handle:
        assert handle["provider"] == "libvirt"
        assert handle["snapshot_id"].endswith("sheshnaag-baseline")
        assert handle["baseline_sha"]
        assert handle["revert_on_exit"] is True
        assert handle["errors"] == []

    # At minimum: one create and one revert + one delete.
    action_verbs = [cmd[1] for cmd in captured_cmds if len(cmd) > 1 and cmd[0] == "virsh"]
    assert "snapshot-create-as" in action_verbs
    assert "snapshot-revert" in action_verbs
    assert "snapshot-delete" in action_verbs


@pytest.mark.unit
def test_lima_snapshot_happy_path(monkeypatch, tmp_path):
    disk = tmp_path / "lima.qcow2"
    disk.write_bytes(b"baseline-disk-bytes")
    profile = _profile(
        provider_hint="lima",
        config={"instance": "sheshnaag-lab", "disk_path": str(disk)},
    )

    monkeypatch.setattr(
        sm_module.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "limactl" else None,
    )
    # Use the real shutil.copy2 so the baseline image gets created/restored.
    monkeypatch.setattr(sm_module.shutil, "copy2", shutil.copy2)

    calls: List[List[str]] = []

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        return _Completed(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sm_module.subprocess, "run", _fake_run)

    mgr = SnapshotManager(profile, run_id="lima-1")
    with mgr.with_snapshot() as handle:
        assert handle["provider"] == "lima"
        assert handle["details"]["instance"] == "sheshnaag-lab"
        baseline_image = handle["details"]["baseline_image"]
        assert baseline_image.endswith(".baseline.qcow2")
        # Mutate the disk "in guest" so we can prove the revert restored it.
        disk.write_bytes(b"mutated-in-guest")

    # After with-block: disk must equal original baseline.
    assert disk.read_bytes() == b"baseline-disk-bytes"
    # limactl was invoked to stop at least twice (create + revert).
    stop_calls = [cmd for cmd in calls if cmd[:3] == ["limactl", "stop", "--force"]]
    assert len(stop_calls) >= 2


@pytest.mark.unit
def test_docker_snapshot_is_noop_revert(monkeypatch):
    profile = _profile(provider_hint="docker", config={"image": "kali:latest"})
    monkeypatch.setattr(
        sm_module.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "docker" else None,
    )

    inspect_calls: List[List[str]] = []

    def _fake_run(cmd, **kwargs):
        inspect_calls.append(list(cmd))
        return _Completed(returncode=0, stdout="sha256:abcd1234", stderr="")

    monkeypatch.setattr(sm_module.subprocess, "run", _fake_run)

    mgr = SnapshotManager(profile, run_id="dk1")
    with mgr.with_snapshot() as handle:
        assert handle["provider"] == "docker"
        assert handle["baseline_sha"] == "sha256:abcd1234"
        assert handle["details"]["revert_is_noop"] is True
        assert "--rm" in handle["details"]["enforced_run_flags"]

    # Revert event must still fire, and must record the no-op outcome.
    revert_events = [evt for evt in mgr.events if evt["event"] == "snapshot_reverted"]
    assert revert_events and revert_events[0]["details"]["revert_is_noop"] is True
    # Only the image-inspect docker call should have been dispatched.
    assert any(cmd[:3] == ["docker", "image", "inspect"] for cmd in inspect_calls)


@pytest.mark.unit
def test_revert_on_exception(monkeypatch):
    profile = _profile(provider_hint="libvirt", config={"domain": "dom-x"})
    monkeypatch.setattr(
        sm_module.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "virsh" else None,
    )

    captured: List[List[str]] = []

    def _fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return _Completed(returncode=0)

    monkeypatch.setattr(sm_module.subprocess, "run", _fake_run)

    mgr = SnapshotManager(profile, run_id="exc")

    with pytest.raises(RuntimeError, match="kaboom"):
        with mgr.with_snapshot():
            raise RuntimeError("kaboom")

    # Even though the body raised, revert must still have run.
    assert any(cmd[:2] == ["virsh", "snapshot-revert"] for cmd in captured)
    events = [evt["event"] for evt in mgr.events]
    assert "snapshot_reverted" in events


@pytest.mark.unit
def test_no_revert_env_var_honored(monkeypatch):
    monkeypatch.setenv("SHESHNAAG_SNAPSHOT_NO_REVERT", "1")
    profile = _profile(provider_hint="libvirt", config={"domain": "dom-noop"})
    monkeypatch.setattr(
        sm_module.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name == "virsh" else None,
    )

    captured: List[List[str]] = []
    monkeypatch.setattr(
        sm_module.subprocess, "run",
        lambda cmd, **kw: captured.append(list(cmd)) or _Completed(),
    )

    mgr = SnapshotManager(profile, run_id="noop")
    with mgr.with_snapshot() as handle:
        assert handle["revert_on_exit"] is False

    # The only virsh call should be snapshot-create-as; revert must NOT fire.
    verbs = [cmd[1] for cmd in captured if cmd[0] == "virsh"]
    assert "snapshot-create-as" in verbs
    assert "snapshot-revert" not in verbs
    event_names = [evt["event"] for evt in mgr.events]
    assert "snapshot_revert_skipped" in event_names
    assert "snapshot_reverted" not in event_names


@pytest.mark.unit
def test_missing_binaries_dry_run(monkeypatch):
    profile = _profile(provider_hint="libvirt", config={"domain": "dom"})
    monkeypatch.setattr(sm_module.shutil, "which", lambda _name: None)

    def _explode(*args, **kwargs):  # pragma: no cover
        raise AssertionError("subprocess.run must not be called when virsh missing")

    monkeypatch.setattr(sm_module.subprocess, "run", _explode)

    mgr = SnapshotManager(profile, run_id="missing")
    with mgr.with_snapshot() as handle:
        assert handle["dry_run"] is True
        assert "virsh not available" in handle["details"]["reason"]
        assert handle["baseline_sha"]

    # Even in dry-run mode, we must still record a revert event.
    assert [evt["event"] for evt in mgr.events] == [
        "snapshot_created",
        "snapshot_reverted",
    ]


@pytest.mark.unit
def test_unknown_provider_falls_back_to_docker(monkeypatch):
    profile = _profile(provider_hint="qemu-x86", config={})
    monkeypatch.setattr(sm_module.shutil, "which", lambda _name: None)
    mgr = SnapshotManager(profile, run_id="fb")
    assert mgr.provider == "docker"

    with mgr.with_snapshot() as handle:
        assert handle["provider"] == "docker"
        assert handle["dry_run"] is True
