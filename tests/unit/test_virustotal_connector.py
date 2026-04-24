"""Unit tests for the VirusTotal v3 IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)
from app.ingestion.virustotal_connector import VirusTotalConnector, _vt_url_id


SAMPLE_VT_FILE = {
    "data": {
        "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "harmless": 40,
                "malicious": 20,
                "suspicious": 3,
                "undetected": 5,
                "timeout": 0,
            },
            "last_analysis_date": 1707600000,
            "reputation": -42,
            "tags": ["peexe", "trojan"],
        },
    }
}


def _mock_response(status_code: int = 200, json_body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body if json_body is not None else {}
    return resp


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_health_false_without_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert VirusTotalConnector().healthy is False


@pytest.mark.unit
def test_health_true_with_api_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    assert VirusTotalConnector().healthy is True


# ---------------------------------------------------------------------------
# fetch() shape
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    session = MagicMock()
    connector = VirusTotalConnector(session=session)
    assert connector.fetch({"iocs": [{"kind": "sha256", "value": "abc"}]}) == []
    session.get.assert_not_called()


@pytest.mark.unit
def test_fetch_file_normalizes_stats():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_VT_FILE)
    connector = VirusTotalConnector(api_key="vt-key", session=session)

    record = connector.fetch_file("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert record is not None
    assert record["source"] == "virustotal"
    assert record["indicator_kind"] == "sha256"
    assert record["stats"]["malicious"] == 20
    assert record["stats"]["harmless"] == 40
    assert record["last_analysis_date"] == 1707600000
    assert record["reputation"] == -42
    assert "trojan" in record["tags"]
    # (20 + 0.5*3) / (40+20+3+5+0) = 21.5/68 ≈ 0.316
    assert 0.30 < record["confidence"] < 0.33

    call = session.get.call_args
    assert call.kwargs["headers"]["x-apikey"] == "vt-key"
    assert call.args[0].endswith("/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


@pytest.mark.unit
def test_fetch_url_uses_urlsafe_b64_id():
    session = MagicMock()
    session.get.return_value = _mock_response(200, {"data": {"attributes": {}}})
    connector = VirusTotalConnector(api_key="vt-key", session=session)

    record = connector.fetch_url("http://evil.example.com/")

    assert record is not None
    assert record["indicator_kind"] == "url"
    expected_id = _vt_url_id("http://evil.example.com/")
    assert session.get.call_args.args[0].endswith(f"/urls/{expected_id}")


@pytest.mark.unit
def test_fetch_domain_and_ip():
    session = MagicMock()
    session.get.return_value = _mock_response(200, {"data": {"attributes": {}}})
    connector = VirusTotalConnector(api_key="vt-key", session=session)

    d = connector.fetch_domain("bad.example")
    assert d["indicator_kind"] == "domain"
    assert session.get.call_args.args[0].endswith("/domains/bad.example")

    i = connector.fetch_ip("198.51.100.1")
    assert i["indicator_kind"] == "ip"
    assert session.get.call_args.args[0].endswith("/ip_addresses/198.51.100.1")


@pytest.mark.unit
def test_fetch_fans_out_over_iocs():
    session = MagicMock()
    session.get.return_value = _mock_response(200, {"data": {"attributes": {}}})
    connector = VirusTotalConnector(api_key="vt-key", session=session)

    records = connector.fetch(
        {
            "iocs": [
                {"kind": "sha256", "value": "a" * 64},
                {"kind": "url", "value": "http://x.example/"},
                {"kind": "domain", "value": "x.example"},
                {"kind": "ip", "value": "192.0.2.1"},
                {"kind": "other", "value": "skip-me"},
            ]
        }
    )
    assert len(records) == 4
    assert {r["indicator_kind"] for r in records} == {"sha256", "url", "domain", "ip"}


# ---------------------------------------------------------------------------
# Rate-limit & errors
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.get.side_effect = [
        _mock_response(429, {}),
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_VT_FILE),
    ]
    connector = VirusTotalConnector(
        api_key="vt-key",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    record = connector.fetch_file("a" * 64)
    assert record is not None
    assert session.get.call_count == 3
    assert len(sleeps) == 2


@pytest.mark.unit
def test_fetch_gives_up_after_persistent_429():
    sleeps: list[float] = []
    session = MagicMock()
    session.get.return_value = _mock_response(429, {})
    connector = VirusTotalConnector(
        api_key="vt-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    assert connector.fetch_file("a" * 64) is None
    assert session.get.call_count == 2


@pytest.mark.unit
def test_fetch_404_returns_none():
    session = MagicMock()
    session.get.return_value = _mock_response(404, {})
    connector = VirusTotalConnector(
        api_key="vt-key",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_file("a" * 64) is None
    assert session.get.call_count == 1


@pytest.mark.unit
def test_fetch_handles_network_error():
    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("boom")
    connector = VirusTotalConnector(
        api_key="vt-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_file("a" * 64) is None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_virustotal_registered():
    assert "virustotal" in get_registered_ioc_connectors()
    assert get_ioc_connector("virustotal") is VirusTotalConnector
