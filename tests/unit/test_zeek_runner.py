"""Unit tests for app.lab.zeek_runner."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from app.lab import zeek_runner as zeek_module
from app.lab.zeek_runner import ZeekRunner


CONN_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring
1700000000.000\tCabc\t10.0.0.5\t51515\t203.0.113.9\t443\ttcp\tssl
1700000001.000\tCdef\t10.0.0.5\t60001\t198.51.100.4\t80\ttcp\thttp
"""

DNS_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\tqtype_name\trcode_name\tanswers
#types\ttime\tstring\taddr\taddr\tstring\tstring\tstring\tvector[string]
1700000000.100\tCabc\t10.0.0.5\t10.0.0.1\tevil.example.com\tA\tNOERROR\t203.0.113.9
"""

HTTP_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\thttp
#fields\tts\tuid\tid.orig_h\tid.resp_h\thost\turi\tmethod\tstatus_code\tuser_agent
#types\ttime\tstring\taddr\taddr\tstring\tstring\tstring\tcount\tstring
1700000002.000\tCdef\t10.0.0.5\t198.51.100.4\texample.test\t/payload.bin\tGET\t200\tcurl/7.85
"""

SSL_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tssl
#fields\tts\tuid\tserver_name\tversion
#types\ttime\tstring\tstring\tstring
1700000003.000\tCxyz\tapi.evil.example.com\tTLSv13
"""

FILES_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tfiles
#fields\tts\tfuid\tmime_type\tfilename\tmd5\tsha1\tsha256
#types\ttime\tstring\tstring\tstring\tstring\tstring\tstring
1700000004.000\tFabc\tapplication/x-dosexec\tpayload.exe\td41d8cd98f00b204e9800998ecf8427e\tda39a3ee5e6b4b0d3255bfef95601890afd80709\te3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""


def _stage_logs(root: Path) -> None:
    (root / "conn.log").write_text(CONN_LOG)
    (root / "dns.log").write_text(DNS_LOG)
    (root / "http.log").write_text(HTTP_LOG)
    (root / "ssl.log").write_text(SSL_LOG)
    (root / "files.log").write_text(FILES_LOG)


@pytest.mark.unit
def test_health_unhealthy_when_binary_missing(monkeypatch):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: None)
    runner = ZeekRunner(zeek_binary="zeek-absent")
    h = runner.health()
    assert h["healthy"] is False
    assert h["reason"] == "binary_not_found"


@pytest.mark.unit
def test_health_healthy_with_version(monkeypatch):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="zeek version 6.0.0\n", stderr="")

    monkeypatch.setattr(zeek_module.subprocess, "run", fake_run)
    runner = ZeekRunner(zeek_binary="zeek")
    h = runner.health()
    assert h["healthy"] is True
    assert "zeek" in (h["version"] or "").lower()


@pytest.mark.unit
def test_run_returns_empty_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: None)
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00")
    runner = ZeekRunner(zeek_binary="zeek-absent")
    result = runner.run(pcap_path=str(pcap))
    assert result["connections"] == []
    assert result["summary"]["counts"]["connections"] == 0


@pytest.mark.unit
def test_run_returns_empty_when_pcap_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")
    runner = ZeekRunner()
    result = runner.run(pcap_path=str(tmp_path / "missing.pcap"))
    assert result["summary"]["counts"] == {
        "connections": 0, "dns": 0, "http": 0, "ssl": 0, "files": 0
    }


@pytest.mark.unit
def test_run_parses_staged_logs(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00")

    workdir = tmp_path / "work"
    workdir.mkdir()

    def fake_run(cmd, capture_output, text, timeout, cwd):
        assert cmd[0] == "/usr/local/bin/zeek"
        assert cmd[1:3] == ["-r", str(pcap)]
        assert cmd[3] == "local"
        # Stage logs into the cwd Zeek is told to use.
        _stage_logs(Path(cwd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(zeek_module.subprocess, "run", fake_run)

    runner = ZeekRunner()
    result = runner.run(pcap_path=str(pcap), workdir=str(workdir))

    assert len(result["connections"]) == 2
    assert result["connections"][0]["id.resp_h"] == "203.0.113.9"
    assert len(result["dns"]) == 1
    assert result["dns"][0]["query"] == "evil.example.com"
    assert len(result["http"]) == 1
    assert result["http"][0]["host"] == "example.test"
    assert len(result["ssl"]) == 1
    assert result["ssl"][0]["server_name"] == "api.evil.example.com"
    assert len(result["files"]) == 1
    assert result["files"][0]["sha256"].startswith("e3b0c442")

    counts = result["summary"]["counts"]
    assert counts["connections"] == 2
    assert counts["dns"] == 1
    assert counts["http"] == 1
    assert counts["ssl"] == 1
    assert counts["files"] == 1
    assert "203.0.113.9" in result["summary"]["uniq_dests"]


@pytest.mark.unit
def test_extract_indicators_dedup_and_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00")
    workdir = tmp_path / "work"
    workdir.mkdir()

    def fake_run(cmd, capture_output, text, timeout, cwd):
        _stage_logs(Path(cwd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(zeek_module.subprocess, "run", fake_run)

    runner = ZeekRunner()
    result = runner.run(pcap_path=str(pcap), workdir=str(workdir))
    indicators = runner.extract_indicators(result)

    # Every indicator has the IndicatorArtifact-shaped keys.
    for ind in indicators:
        assert set(ind.keys()) >= {"indicator_kind", "value", "source", "confidence", "payload"}
        assert ind["source"] == "zeek"
        assert 0.0 <= ind["confidence"] <= 1.0

    # Dedup: "203.0.113.9" appears in both conn.log and dns.log answers.
    values_203 = [ind for ind in indicators if ind["value"] == "203.0.113.9"]
    assert len(values_203) == 1
    # DNS answer gives it higher confidence than a bare connection row.
    assert values_203[0]["indicator_kind"] == "ip"
    assert values_203[0]["confidence"] >= 0.7

    kinds = {ind["indicator_kind"] for ind in indicators}
    assert "domain" in kinds
    assert "url" in kinds
    assert "file_hash_sha256" in kinds

    urls = [ind for ind in indicators if ind["indicator_kind"] == "url"]
    assert any("example.test/payload.bin" in ind["value"] for ind in urls)


@pytest.mark.unit
def test_empty_pcap_produces_no_logs(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"")
    workdir = tmp_path / "work"
    workdir.mkdir()

    def fake_run(cmd, capture_output, text, timeout, cwd):
        # Zeek succeeds but produces no log files.
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(zeek_module.subprocess, "run", fake_run)

    runner = ZeekRunner()
    result = runner.run(pcap_path=str(pcap), workdir=str(workdir))
    assert result["summary"]["counts"] == {
        "connections": 0, "dns": 0, "http": 0, "ssl": 0, "files": 0
    }
    assert runner.extract_indicators(result) == []


@pytest.mark.unit
def test_run_handles_zeek_nonzero_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(zeek_module.shutil, "which", lambda _: "/usr/local/bin/zeek")
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\x00")
    workdir = tmp_path / "work"
    workdir.mkdir()

    def fake_run(cmd, capture_output, text, timeout, cwd):
        return subprocess.CompletedProcess(args=cmd, returncode=2, stdout="", stderr="boom")

    monkeypatch.setattr(zeek_module.subprocess, "run", fake_run)

    runner = ZeekRunner()
    result = runner.run(pcap_path=str(pcap), workdir=str(workdir))
    assert result["summary"]["counts"]["connections"] == 0
