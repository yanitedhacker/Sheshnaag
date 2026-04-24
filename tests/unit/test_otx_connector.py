"""Unit tests for the AlienVault OTX IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)
from app.ingestion.otx_connector import OTXConnector


SAMPLE_PULSES = {
    "results": [
        {
            "id": "pulse-001",
            "name": "APT42 campaign",
            "tags": ["apt42", "phishing"],
            "created": "2024-02-01T10:00:00Z",
            "modified": "2024-02-05T12:00:00Z",
            "indicators": [
                {
                    "type": "IPv4",
                    "indicator": "198.51.100.5",
                    "created": "2024-02-01T10:05:00Z",
                },
                {
                    "type": "FileHash-SHA256",
                    "indicator": "b" * 64,
                },
                {
                    "type": "domain",
                    "indicator": "c2.example",
                },
            ],
        }
    ]
}


SAMPLE_INDICATOR = {
    "pulse_info": {
        "count": 5,
        "pulses": [
            {"tags": ["malware", "loader"]},
            {"tags": ["loader", "emotet"]},
        ],
    },
    "first_seen": "2024-01-01T00:00:00Z",
    "last_seen": "2024-02-10T00:00:00Z",
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
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    assert OTXConnector().healthy is False


@pytest.mark.unit
def test_health_true_with_env(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")
    assert OTXConnector().healthy is True


# ---------------------------------------------------------------------------
# Fetch without env
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    session = MagicMock()
    connector = OTXConnector(session=session)
    assert connector.fetch({"mode": "pulses"}) == []
    session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Pulses
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_pulses_normalizes_indicators():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_PULSES)
    connector = OTXConnector(api_key="otx-key", session=session)

    records = connector.fetch({"mode": "pulses", "limit": 5})

    assert len(records) == 3
    ip_row = next(r for r in records if r["indicator_kind"] == "ip")
    assert ip_row["value"] == "198.51.100.5"
    assert ip_row["event_id"] == "pulse-001"
    assert ip_row["event_info"] == "APT42 campaign"
    assert "apt42" in ip_row["tags"]
    sha = next(r for r in records if r["indicator_kind"] == "sha256")
    assert sha["value"] == "b" * 64
    dom = next(r for r in records if r["indicator_kind"] == "domain")
    assert dom["value"] == "c2.example"

    call = session.get.call_args
    assert call.kwargs["headers"]["X-OTX-API-KEY"] == "otx-key"
    assert call.args[0].endswith("/pulses/subscribed")
    assert call.kwargs["params"]["limit"] == 5


# ---------------------------------------------------------------------------
# Indicator lookup
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_indicator_general():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_INDICATOR)
    connector = OTXConnector(api_key="otx-key", session=session)

    records = connector.fetch(
        {
            "mode": "indicators",
            "iocs": [
                {"kind": "ip", "value": "198.51.100.5"},
                {"kind": "sha256", "value": "b" * 64},
            ],
        }
    )
    assert len(records) == 2
    first = records[0]
    assert first["source"] == "otx"
    assert first["indicator_kind"] == "ip"
    assert first["value"] == "198.51.100.5"
    assert first["pulse_count"] == 5
    assert "malware" in first["tags"] and "loader" in first["tags"]
    assert first["confidence"] > 0.5

    urls = [call.args[0] for call in session.get.call_args_list]
    assert any("/indicators/IPv4/198.51.100.5/general" in u for u in urls)
    assert any(f"/indicators/file/{'b' * 64}/general" in u for u in urls)


# ---------------------------------------------------------------------------
# Error / rate-limit handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.get.side_effect = [
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_PULSES),
    ]
    connector = OTXConnector(
        api_key="otx-key",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    assert len(connector.fetch({"mode": "pulses"})) == 3
    assert session.get.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.unit
def test_fetch_returns_empty_on_5xx():
    session = MagicMock()
    session.get.return_value = _mock_response(503, {})
    connector = OTXConnector(
        api_key="otx-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch({"mode": "pulses"}) == []


@pytest.mark.unit
def test_fetch_returns_empty_on_network_error():
    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("boom")
    connector = OTXConnector(
        api_key="otx-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch({"mode": "pulses"}) == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_otx_registered():
    assert "otx" in get_registered_ioc_connectors()
    assert get_ioc_connector("otx") is OTXConnector
