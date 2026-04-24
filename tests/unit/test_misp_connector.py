"""Unit tests for the MISP IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.ingestion.misp_connector import (
    MISPConnector,
    get_ioc_connector,
    get_registered_ioc_connectors,
)


SAMPLE_MISP_RESPONSE = {
    "response": [
        {
            "Event": {
                "id": "42",
                "uuid": "5f3e-...",
                "info": "Emotet campaign -- Feb 2024",
                "date": "2024-02-10",
                "timestamp": "1707628800",
                "threat_level_id": "2",
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": "malware:emotet"},
                ],
                "Attribute": [
                    {
                        "id": "101",
                        "type": "ip-dst",
                        "value": "198.51.100.24",
                        "to_ids": True,
                        "timestamp": "1707629000",
                        "first_seen": "2024-02-10T00:00:00Z",
                        "last_seen": "2024-02-11T00:00:00Z",
                        "Tag": [{"name": "c2"}],
                    },
                    {
                        "id": "102",
                        "type": "sha256",
                        "value": "a" * 64,
                        "to_ids": True,
                        "timestamp": "1707629100",
                    },
                    {
                        "id": "103",
                        "type": "url",
                        "value": "http://evil.example.com/pw",
                        "to_ids": False,
                        "timestamp": "1707629200",
                    },
                ],
                "Object": [
                    {
                        "Attribute": [
                            {
                                "type": "domain",
                                "value": "bad-infra.example",
                                "to_ids": True,
                            }
                        ]
                    }
                ],
            }
        }
    ]
}


def _mock_response(status_code: int = 200, json_body=None, text: str = ""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_health_false_when_env_missing(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)
    connector = MISPConnector()
    assert connector.healthy is False


@pytest.mark.unit
def test_health_false_when_only_url_set(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.org")
    monkeypatch.delenv("MISP_KEY", raising=False)
    connector = MISPConnector()
    assert connector.healthy is False


@pytest.mark.unit
def test_health_true_when_both_env_set(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.org")
    monkeypatch.setenv("MISP_KEY", "secret-token")
    connector = MISPConnector()
    assert connector.healthy is True


# ---------------------------------------------------------------------------
# Fetch -- env missing
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_KEY", raising=False)
    session = MagicMock()
    connector = MISPConnector(session=session)
    assert connector.fetch({}) == []
    session.post.assert_not_called()


# ---------------------------------------------------------------------------
# Fetch -- happy path
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_normalized_records(monkeypatch):
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_MISP_RESPONSE)
    connector = MISPConnector(
        base_url="https://misp.example.org",
        api_key="sekret",
        session=session,
    )

    records = connector.fetch({"limit": 25, "tags": ["tlp:amber"]})

    # 3 direct attributes + 1 object attribute
    assert len(records) == 4
    first = records[0]
    assert first["source"] == "misp"
    assert first["event_id"] == "42"
    assert first["event_info"].startswith("Emotet")
    assert first["indicator_kind"] == "ip"
    assert first["value"] == "198.51.100.24"
    assert "tlp:amber" in first["tags"]
    assert "c2" in first["tags"]
    assert 0.0 <= first["confidence"] <= 1.0

    # sha256 mapping
    sha_row = next(r for r in records if r["value"] == "a" * 64)
    assert sha_row["indicator_kind"] == "sha256"

    # URL mapping
    url_row = next(r for r in records if r["indicator_kind"] == "url")
    assert url_row["value"] == "http://evil.example.com/pw"

    # Object attribute folded in
    domain_row = next(r for r in records if r["indicator_kind"] == "domain")
    assert domain_row["value"] == "bad-infra.example"

    # POST request shape
    call = session.post.call_args
    assert call.args[0] == "https://misp.example.org/events/restSearch"
    assert call.kwargs["headers"]["Authorization"] == "sekret"
    assert call.kwargs["headers"]["Accept"] == "application/json"
    assert call.kwargs["json"]["limit"] == 25
    assert call.kwargs["json"]["tags"] == ["tlp:amber"]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_handles_5xx(monkeypatch):
    session = MagicMock()
    session.post.return_value = _mock_response(500, {}, text="server on fire")
    connector = MISPConnector(
        base_url="https://misp.example.org",
        api_key="sekret",
        session=session,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_handles_429(monkeypatch):
    session = MagicMock()
    session.post.return_value = _mock_response(429, {}, text="slow down")
    connector = MISPConnector(
        base_url="https://misp.example.org",
        api_key="sekret",
        session=session,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_handles_network_error(monkeypatch):
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("boom")
    connector = MISPConnector(
        base_url="https://misp.example.org",
        api_key="sekret",
        session=session,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_handles_bad_json(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("not json")
    resp.text = "<html>oops</html>"
    session = MagicMock()
    session.post.return_value = resp
    connector = MISPConnector(
        base_url="https://misp.example.org",
        api_key="sekret",
        session=session,
    )
    assert connector.fetch({}) == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_misp_registered():
    assert "misp" in get_registered_ioc_connectors()
    assert get_ioc_connector("misp") is MISPConnector
