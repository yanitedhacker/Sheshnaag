"""Unit tests for the V4 launcher dispatch layer."""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.lab.launchers import (
    ArchiveLauncher,
    BrowserLauncher,
    ElfLauncher,
    EmailLauncher,
    LauncherResult,
    PeLauncher,
    UrlLauncher,
    dispatch_launcher,
)


def _completed(rc: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = rc
    m.stdout = stdout
    m.stderr = stderr
    return m


def _make_inputs(tmp_path, **overrides):
    """Build the minimum set of kw-arguments every launcher needs."""

    revision = SimpleNamespace(
        id=1,
        quarantine_path=str(tmp_path / "specimen.bin"),
        content_ref="https://example.test/payload",
        metadata_json={},
        safe_rendering={},
        static_triage={},
    )
    # Touch the specimen file so recursive launchers that enumerate the
    # disk see something.
    (tmp_path / "specimen.bin").write_bytes(b"\x4d\x5a")
    base = {
        "specimen": SimpleNamespace(id=7, name="sample", specimen_kind="file"),
        "revision": revision,
        "profile": SimpleNamespace(config={"detonation_timeout_s": 5}),
        "run": SimpleNamespace(id=42),
        "quarantine_path": str(tmp_path),
        "egress": None,
        "snapshot_snap": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# dispatch_launcher routing
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kind", "metadata", "expected_cls"),
    [
        ("url", {}, UrlLauncher),
        ("email/eml", {}, EmailLauncher),
        ("email", {}, EmailLauncher),
        ("archive/zip", {}, ArchiveLauncher),
        ("archive", {}, ArchiveLauncher),
        ("file/pe", {}, PeLauncher),
        ("file/msi", {}, PeLauncher),
        ("file/elf", {}, ElfLauncher),
        ("file/script", {}, ElfLauncher),
        ("file/js", {}, BrowserLauncher),
        ("file/hta", {}, BrowserLauncher),
        ("file", {"mime_type": "application/x-dosexec"}, PeLauncher),
        ("file", {"mime_type": "application/x-executable"}, ElfLauncher),
        ("file", {"mime_type": "application/javascript"}, BrowserLauncher),
    ],
)
def test_dispatch_launcher_routes_by_kind_and_mime(kind, metadata, expected_cls):
    launcher = dispatch_launcher(kind, metadata)
    assert isinstance(launcher, expected_cls)


@pytest.mark.unit
def test_dispatch_launcher_raises_for_unknown_kind():
    with pytest.raises(ValueError):
        dispatch_launcher("mystery/unknown", {})


# ---------------------------------------------------------------------------
# Happy-path launcher smoke tests (all subprocess calls mocked).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_pe_launcher_libvirt_path(tmp_path):
    launcher = PeLauncher()
    inputs = _make_inputs(tmp_path)
    with patch("app.lab.launchers.pe_launcher.shutil.which", return_value="/usr/bin/virsh"), patch(
        "app.lab.launchers.pe_launcher.subprocess.run",
        return_value=_completed(rc=0),
    ) as run_mock:
        result = launcher.launch(**inputs)
    assert isinstance(result, LauncherResult)
    assert result.exit_code == 0
    # virsh start, winexe/psexec/wmic, virsh dump — at least two calls.
    assert run_mock.call_count >= 2
    assert result.metadata["mode"] == "libvirt"


@pytest.mark.unit
def test_pe_launcher_dry_run_when_no_binaries(tmp_path):
    launcher = PeLauncher()
    inputs = _make_inputs(tmp_path)
    with patch("app.lab.launchers.pe_launcher.shutil.which", return_value=None):
        result = launcher.launch(**inputs)
    assert result.metadata["mode"] == "dry-run"
    assert result.pcap_path is None


@pytest.mark.unit
def test_elf_launcher_docker_path(tmp_path):
    launcher = ElfLauncher()
    inputs = _make_inputs(tmp_path)
    with patch("app.lab.launchers.elf_launcher.shutil.which", return_value="/usr/bin/docker"), patch(
        "app.lab.launchers.elf_launcher.subprocess.run",
        return_value=_completed(rc=0),
    ) as run_mock:
        result = launcher.launch(**inputs)
    assert result.metadata["mode"] == "docker"
    assert run_mock.call_count == 1
    argv = run_mock.call_args.args[0]
    assert argv[0] == "docker"
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--read-only" in argv


@pytest.mark.unit
def test_browser_launcher_docker_path(tmp_path):
    launcher = BrowserLauncher()
    inputs = _make_inputs(tmp_path)
    with patch("app.lab.launchers.browser_launcher.shutil.which", return_value="/usr/bin/docker"), patch(
        "app.lab.launchers.browser_launcher.subprocess.run",
        return_value=_completed(rc=0),
    ) as run_mock:
        result = launcher.launch(**inputs)
    assert result.metadata["mode"] == "docker-chromium"
    argv = run_mock.call_args.args[0]
    assert "chromium" in argv


@pytest.mark.unit
def test_email_launcher_parses_eml_attachments(tmp_path):
    # Build a minimal .eml with one attachment so the launcher has work.
    eml_path = tmp_path / "sample.eml"
    eml_path.write_bytes(
        b"From: a@b\r\nTo: c@d\r\nSubject: t\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BB"\r\n'
        b"\r\n--BB\r\n"
        b"Content-Type: text/plain\r\n\r\nhello\r\n"
        b"--BB\r\n"
        b'Content-Type: application/octet-stream; name="child.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
        b'Content-Disposition: attachment; filename="child.bin"\r\n'
        b"\r\nSGVsbG8=\r\n"
        b"--BB--\r\n"
    )
    revision = SimpleNamespace(
        id=1,
        quarantine_path=str(eml_path),
        content_ref="mailto:sample",
        metadata_json={},
        safe_rendering={},
        static_triage={},
    )
    inputs = _make_inputs(tmp_path, revision=revision)
    inputs["specimen"] = SimpleNamespace(id=1, name="mail", specimen_kind="email/eml")

    launcher = EmailLauncher()
    with patch("app.lab.launchers.email_launcher.shutil.which", return_value=None):
        result = launcher.launch(**inputs)
    assert result.metadata["launcher"] == "email"
    assert any(p.endswith("child.bin") for p in result.artifacts)


@pytest.mark.unit
def test_archive_launcher_extracts_zip(tmp_path):
    import zipfile

    archive_path = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("inside.txt", "content")

    revision = SimpleNamespace(
        id=1,
        quarantine_path=str(archive_path),
        content_ref=str(archive_path),
        metadata_json={},
        safe_rendering={},
        static_triage={},
    )
    inputs = _make_inputs(tmp_path, revision=revision)
    inputs["specimen"] = SimpleNamespace(id=1, name="zip", specimen_kind="archive/zip")

    launcher = ArchiveLauncher()
    result = launcher.launch(**inputs)
    assert result.exit_code == 0
    assert result.metadata["extracted_count"] >= 1
    assert any(a.endswith("inside.txt") for a in result.artifacts)


@pytest.mark.unit
def test_url_launcher_docker_path(tmp_path):
    launcher = UrlLauncher()
    inputs = _make_inputs(tmp_path)
    inputs["specimen"] = SimpleNamespace(id=1, name="phish", specimen_kind="url")
    inputs["revision"].content_ref = "https://phish.test/"

    popen_mock = MagicMock()
    popen_mock.pid = 1234
    popen_mock.terminate = MagicMock()
    popen_mock.wait = MagicMock()
    with patch("app.lab.launchers.url_launcher.shutil.which", return_value="/usr/bin/docker"), patch(
        "app.lab.launchers.url_launcher.subprocess.Popen", return_value=popen_mock
    ), patch(
        "app.lab.launchers.url_launcher.subprocess.run",
        return_value=_completed(rc=0),
    ) as run_mock:
        result = launcher.launch(**inputs)
    assert result.metadata["mode"] == "docker-chromium"
    assert run_mock.call_count == 1
    argv = run_mock.call_args.args[0]
    assert argv[0] == "docker"
    assert any("https://phish.test/" in str(a) for a in argv)
    popen_mock.terminate.assert_called_once()
