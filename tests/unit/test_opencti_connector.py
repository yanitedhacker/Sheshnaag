"""Unit tests for the OpenCTI IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)
from app.ingestion.opencti_connector import OpenCTIConnector


SAMPLE_INDICATORS_RESPONSE = {
    "data": {
        "indicators": {
            "edges": [
                {
                    "node": {
                        "id": "indicator--aaa",
                        "standard_id": "indicator--aaa-std",
                        "entity_type": "Indicator",
                        "pattern": "[ipv4-addr:value = '198.51.100.22']",
                        "pattern_type": "stix",
                        "name": "198.51.100.22",
                        "description": "C2 node",
                        "x_opencti_score": 85,
                        "confidence": 70,
                        "valid_from": "2024-02-10T00:00:00Z",
                        "valid_until": "2024-05-10T00:00:00Z",
                        "created_at": "2024-02-10T00:00:00Z",
                        "updated_at": "2024-02-12T00:00:00Z",
                        "revoked": False,
                        "x_opencti_main_observable_type": "IPv4-Addr",
                        "objectLabel": [
                            {"value": "apt42"},
                            {"value": "c2"},
                        ],
                        "objectMarking": [
                            {"definition": "TLP:AMBER"},
                        ],
                    }
                },
                {
                    "node": {
                        "id": "indicator--bbb",
                        "entity_type": "Indicator",
                        "pattern": "[file:hashes.'SHA-256' = 'a" + "a" * 63 + "']",
                        "pattern_type": "stix",
                        "name": None,
                        "x_opencti_score": 50,
                        "confidence": 50,
                        "valid_from": "2024-02-01T00:00:00Z",
                        "created_at": "2024-02-01T00:00:00Z",
                        "updated_at": "2024-02-02T00:00:00Z",
                        "x_opencti_main_observable_type": "StixFile",
                        "objectLabel": [],
                        "objectMarking": [],
                    }
                },
                {
                    "node": {
                        "id": "indicator--ccc",
                        "entity_type": "Indicator",
                        "pattern": "[domain-name:value = 'bad.example']",
                        "name": "bad.example",
                        "x_opencti_score": None,
                        "confidence": 30,
                        "x_opencti_main_observable_type": "Domain-Name",
                        "objectLabel": [{"value": "phishing"}],
                        "objectMarking": [],
                    }
                },
            ],
            "pageInfo": {"endCursor": "cursor-1", "hasNextPage": False},
        }
    }
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
    monkeypatch.delenv("OPENCTI_URL", raising=False)
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    assert OpenCTIConnector().healthy is False


@pytest.mark.unit
def test_health_false_when_only_url_set(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "https://opencti.example.org")
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    assert OpenCTIConnector().healthy is False


@pytest.mark.unit
def test_health_true_when_both_env_set(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "https://opencti.example.org")
    monkeypatch.setenv("OPENCTI_TOKEN", "tok-123")
    assert OpenCTIConnector().healthy is True


# ---------------------------------------------------------------------------
# Fetch -- env missing
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("OPENCTI_URL", raising=False)
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    session = MagicMock()
    connector = OpenCTIConnector(session=session)
    assert connector.fetch({}) == []
    session.post.assert_not_called()


# ---------------------------------------------------------------------------
# Fetch -- happy path
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_normalized_records():
    session = MagicMock()
    session.post.return_value = _mock_response(200, SAMPLE_INDICATORS_RESPONSE)
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
    )

    records = connector.fetch(
        {
            "first": 25,
            "labels": ["apt42"],
            "min_score": 50,
            "created_since": "2024-01-01T00:00:00Z",
        }
    )

    assert len(records) == 3

    ip_row = next(r for r in records if r["indicator_kind"] == "ip")
    assert ip_row["source"] == "opencti"
    assert ip_row["value"] == "198.51.100.22"
    assert ip_row["confidence"] == 0.85
    assert "apt42" in ip_row["labels"]
    assert "c2" in ip_row["labels"]
    assert "TLP:AMBER" in ip_row["tags"]
    assert ip_row["first_seen"] == "2024-02-10T00:00:00Z"
    assert ip_row["last_seen"] == "2024-05-10T00:00:00Z"
    assert ip_row["payload"]["pattern_type"] == "stix"
    assert ip_row["payload"]["x_opencti_score"] == 85

    # SHA256 detected via pattern inspection
    sha_row = next(r for r in records if r["indicator_kind"] == "sha256")
    assert sha_row["value"].startswith("a")
    assert len(sha_row["value"]) == 64
    assert sha_row["confidence"] == 0.5

    # Domain row falls back to 'confidence' field when score is None
    dom_row = next(r for r in records if r["indicator_kind"] == "domain")
    assert dom_row["value"] == "bad.example"
    assert dom_row["confidence"] == 0.3

    # POST request shape
    call = session.post.call_args
    assert call.args[0] == "https://opencti.example.org/graphql"
    assert call.kwargs["headers"]["Authorization"] == "Bearer tok-123"
    assert call.kwargs["headers"]["Content-Type"] == "application/json"
    sent = call.kwargs["json"]
    assert "query" in sent
    assert sent["variables"]["first"] == 25
    # Filters composed for labels, min_score, created_since
    filters_group = sent["variables"].get("filters") or {}
    keys = [f.get("key") for f in filters_group.get("filters") or []]
    assert "objectLabel" in keys
    assert "x_opencti_score" in keys
    assert "created_at" in keys


# ---------------------------------------------------------------------------
# Error / rate-limit handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_handles_5xx_with_retries():
    sleeps: list[float] = []
    session = MagicMock()
    session.post.return_value = _mock_response(503, {}, text="try later")
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    assert connector.fetch({}) == []
    assert session.post.call_count == 2


@pytest.mark.unit
def test_fetch_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.post.side_effect = [
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_INDICATORS_RESPONSE),
    ]
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    assert len(connector.fetch({})) == 3
    assert session.post.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.unit
def test_fetch_handles_network_error():
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("boom")
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_handles_graphql_errors():
    session = MagicMock()
    session.post.return_value = _mock_response(
        200,
        {"errors": [{"message": "invalid filter"}], "data": None},
    )
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_handles_bad_json():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("nope")
    resp.text = "<html>oops</html>"
    session = MagicMock()
    session.post.return_value = resp
    connector = OpenCTIConnector(
        base_url="https://opencti.example.org",
        token="tok-123",
        session=session,
    )
    assert connector.fetch({}) == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_opencti_registered():
    assert "opencti" in get_registered_ioc_connectors()
    assert get_ioc_connector("opencti") is OpenCTIConnector
