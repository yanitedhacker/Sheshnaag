"""Unit tests for the abuse.ch (URLhaus + MalwareBazaar + ThreatFox) connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.abusech_connector import AbuseChConnector
from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)


SAMPLE_URLHAUS = {
    "query_status": "ok",
    "urls": [
        {
            "id": "1001",
            "url": "http://bad.example/pw.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["emotet"],
            "date_added": "2024-02-10 10:00:00",
            "last_online": "2024-02-12 10:00:00",
        },
        {
            "id": "1002",
            "url": "http://other.example/x",
            "url_status": "offline",
            "threat": "phishing",
            "tags": [],
            "date_added": "2024-02-11 10:00:00",
        },
    ],
}


SAMPLE_MB = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "a" * 64,
            "file_name": "sample.exe",
            "signature": "Emotet",
            "tags": ["exe"],
            "first_seen": "2024-02-01 10:00:00",
            "last_seen": "2024-02-05 10:00:00",
        },
        {
            "sha256_hash": "b" * 64,
            "file_name": "doc.xls",
            "signature": None,
            "tags": [],
            "first_seen": "2024-02-02 10:00:00",
        },
    ],
}


SAMPLE_TF = {
    "query_status": "ok",
    "data": [
        {
            "id": "42",
            "ioc": "198.51.100.5:443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware_printable": "Qakbot",
            "tags": ["qakbot"],
            "confidence_level": 80,
            "first_seen": "2024-02-10 00:00:00",
            "last_seen": "2024-02-11 00:00:00",
        },
        {
            "id": "43",
            "ioc": "bad.example",
            "ioc_type": "domain",
            "threat_type": "c2",
            "malware_printable": "Cobalt Strike",
            "tags": [],
            "confidence_level": 60,
            "first_seen": "2024-02-09 00:00:00",
        },
    ],
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
def test_health_false_without_env(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    assert AbuseChConnector().healthy is False


@pytest.mark.unit
def test_health_true_with_env(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    assert AbuseChConnector().healthy is True


# ---------------------------------------------------------------------------
# Fetch without env
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    session = MagicMock()
    connector = AbuseChConnector(session=session)
    assert connector.fetch() == []
    session.post.assert_not_called()


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_urlhaus_normalizes():
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_URLHAUS)
    connector = AbuseChConnector(auth_key="k", session=session)

    records = connector.fetch_urlhaus(limit=50)

    assert len(records) == 2
    assert records[0]["source"] == "urlhaus"
    assert records[0]["indicator_kind"] == "url"
    assert records[0]["value"] == "http://bad.example/pw.exe"
    assert "emotet" in records[0]["tags"]
    assert records[0]["confidence"] == 0.85  # online
    assert records[1]["confidence"] == 0.5   # offline

    call = session.post.call_args
    assert call.args[0] == "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    assert call.kwargs["headers"]["Auth-Key"] == "k"
    assert call.kwargs["data"] == {"limit": "50"}


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_malwarebazaar_normalizes():
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_MB)
    connector = AbuseChConnector(auth_key="k", session=session)

    records = connector.fetch_malwarebazaar(limit=10)

    assert len(records) == 2
    assert records[0]["source"] == "malwarebazaar"
    assert records[0]["indicator_kind"] == "sha256"
    assert records[0]["value"] == "a" * 64
    assert "Emotet" in records[0]["tags"]
    assert records[0]["confidence"] == 0.9

    call = session.post.call_args
    assert call.args[0] == "https://mb-api.abuse.ch/api/v1/"
    assert call.kwargs["data"] == {"query": "get_recent", "selector": "time"}


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_threatfox_normalizes():
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_TF)
    connector = AbuseChConnector(auth_key="k", session=session)

    records = connector.fetch_threatfox(days=2)

    assert len(records) == 2
    assert records[0]["source"] == "threatfox"
    assert records[0]["indicator_kind"] == "ip"
    assert records[0]["value"] == "198.51.100.5:443"
    assert records[0]["confidence"] == 0.8
    assert "Qakbot" in records[0]["tags"]
    assert records[1]["indicator_kind"] == "domain"

    call = session.post.call_args
    assert call.args[0] == "https://threatfox-api.abuse.ch/api/v1/"
    assert call.kwargs["json"] == {"query": "get_iocs", "days": 2}


# ---------------------------------------------------------------------------
# Generic fetch
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_runs_all_three_sources_by_default():
    session = MagicMock()
    session.post.side_effect = [
        _mock_response(200, SAMPLE_URLHAUS),
        _mock_response(200, SAMPLE_MB),
        _mock_response(200, SAMPLE_TF),
    ]
    connector = AbuseChConnector(auth_key="k", session=session)
    records = connector.fetch()
    sources = {r["source"] for r in records}
    assert sources == {"urlhaus", "malwarebazaar", "threatfox"}


@pytest.mark.unit
def test_fetch_runs_subset_when_sources_specified():
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_TF)
    connector = AbuseChConnector(auth_key="k", session=session)
    records = connector.fetch({"sources": ["threatfox"], "threatfox_days": 1})
    assert all(r["source"] == "threatfox" for r in records)
    assert session.post.call_count == 1


# ---------------------------------------------------------------------------
# Rate-limit / errors
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.post.side_effect = [
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_URLHAUS),
    ]
    connector = AbuseChConnector(
        auth_key="k",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    records = connector.fetch_urlhaus(limit=10)
    assert len(records) == 2
    assert session.post.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.unit
def test_fetch_returns_empty_on_persistent_5xx():
    session = MagicMock()
    session.post.return_value = _mock_response(503, {})
    connector = AbuseChConnector(
        auth_key="k",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_urlhaus() == []


@pytest.mark.unit
def test_fetch_returns_empty_on_network_error():
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("boom")
    connector = AbuseChConnector(
        auth_key="k",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_urlhaus() == []


@pytest.mark.unit
def test_fetch_returns_empty_on_bad_query_status():
    session = MagicMock()
    session.post.return_value = _mock_response(200, {"query_status": "no_results"})
    connector = AbuseChConnector(auth_key="k", session=session)
    assert connector.fetch_urlhaus() == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_abusech_registered():
    assert "abusech" in get_registered_ioc_connectors()
    assert get_ioc_connector("abusech") is AbuseChConnector
