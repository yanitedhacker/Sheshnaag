"""Unit tests for the Mandiant Advantage IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.mandiant_connector import MandiantConnector
from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)


SAMPLE_INDICATORS = {
    "indicators": [
        {
            "id": "indicator--42",
            "type": "ipv4",
            "value": "203.0.113.9",
            "mscore": 92,
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-02-15T00:00:00Z",
            "threat_actors": [
                {"id": "threat-actor--apt42", "name": "APT42", "aliases": ["Charming Kitten"]},
            ],
            "malware_families": [
                {"id": "malware--powerstar", "name": "POWERSTAR", "aliases": []},
            ],
            "sources": [
                {"category": ["command and control", "malware"]},
            ],
        },
        {
            "id": "indicator--43",
            "type": "sha256",
            "value": "a" * 64,
            "mscore": 75,
            "first_seen": "2024-02-01T00:00:00Z",
            "threat_actors": [],
            "malware_families": [{"name": "Emotet"}],
        },
        {
            "id": "indicator--44",
            "type": "fqdn",
            "value": "evil.example",
            "mscore": None,
        },
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
    monkeypatch.delenv("MANDIANT_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("MANDIANT_KEY", raising=False)
    monkeypatch.delenv("MANDIANT_SECRET", raising=False)
    assert MandiantConnector().healthy is False


@pytest.mark.unit
def test_health_false_when_only_key_set(monkeypatch):
    monkeypatch.delenv("MANDIANT_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("MANDIANT_KEY", "k")
    monkeypatch.delenv("MANDIANT_SECRET", raising=False)
    assert MandiantConnector().healthy is False


@pytest.mark.unit
def test_health_true_with_access_token(monkeypatch):
    monkeypatch.setenv("MANDIANT_ACCESS_TOKEN", "tok-abc")
    assert MandiantConnector().healthy is True


@pytest.mark.unit
def test_health_true_with_key_and_secret(monkeypatch):
    monkeypatch.delenv("MANDIANT_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("MANDIANT_KEY", "k")
    monkeypatch.setenv("MANDIANT_SECRET", "s")
    assert MandiantConnector().healthy is True


# ---------------------------------------------------------------------------
# Fetch -- env missing
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("MANDIANT_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("MANDIANT_KEY", raising=False)
    monkeypatch.delenv("MANDIANT_SECRET", raising=False)
    session = MagicMock()
    connector = MandiantConnector(session=session)
    assert connector.fetch({}) == []
    session.request.assert_not_called()


# ---------------------------------------------------------------------------
# Fetch -- happy path with pre-issued bearer token
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_normalized_records():
    session = MagicMock()
    session.request.return_value = _mock_response(200, SAMPLE_INDICATORS)
    connector = MandiantConnector(
        access_token="tok-abc",
        session=session,
    )

    records = connector.fetch({"limit": 20, "gte_mscore": 60})

    assert len(records) == 3

    ip_row = next(r for r in records if r["indicator_kind"] == "ip")
    assert ip_row["source"] == "mandiant"
    assert ip_row["value"] == "203.0.113.9"
    assert ip_row["confidence"] == 0.92
    assert "APT42" in ip_row["tags"]
    assert "POWERSTAR" in ip_row["tags"]
    assert "command and control" in ip_row["labels"]
    actors = ip_row["payload"]["threat_actors"]
    assert actors[0]["name"] == "APT42"
    assert actors[0]["aliases"] == ["Charming Kitten"]

    sha_row = next(r for r in records if r["indicator_kind"] == "sha256")
    assert sha_row["confidence"] == 0.75
    assert "Emotet" in sha_row["tags"]

    # Missing mscore defaults to 0.5
    fqdn_row = next(r for r in records if r["indicator_kind"] == "domain")
    assert fqdn_row["confidence"] == 0.5

    call = session.request.call_args
    assert call.args[0] == "GET"
    assert call.args[1].endswith("/indicator")
    assert call.kwargs["headers"]["Authorization"] == "Bearer tok-abc"
    assert call.kwargs["headers"]["X-App-Name"] == "sheshnaag"
    assert call.kwargs["params"]["limit"] == 20
    assert call.kwargs["params"]["gte_mscore"] == 60


# ---------------------------------------------------------------------------
# Token exchange path
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_exchanges_key_and_secret_for_token():
    session = MagicMock()
    # Token-exchange call first, then the /indicator GET.
    session.post.return_value = _mock_response(
        200, {"access_token": "exchanged-tok", "expires_in": 3600}
    )
    session.request.return_value = _mock_response(200, SAMPLE_INDICATORS)
    connector = MandiantConnector(
        key="id",
        secret="secret",
        session=session,
    )

    records = connector.fetch({"limit": 5})
    assert len(records) == 3

    # POST /token
    post_call = session.post.call_args
    assert post_call.args[0].endswith("/token")
    assert post_call.kwargs["auth"] == ("id", "secret")
    assert post_call.kwargs["headers"]["X-App-Name"] == "sheshnaag"

    # Subsequent indicator GET carries the freshly-exchanged bearer
    req_call = session.request.call_args
    assert req_call.kwargs["headers"]["Authorization"] == "Bearer exchanged-tok"


@pytest.mark.unit
def test_token_exchange_failure_returns_empty():
    session = MagicMock()
    session.post.return_value = _mock_response(500, {}, text="broken")
    connector = MandiantConnector(
        key="id",
        secret="secret",
        session=session,
    )
    assert connector.fetch({}) == []


# ---------------------------------------------------------------------------
# Actor / malware lookups
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_actor_and_malware():
    session = MagicMock()
    session.request.side_effect = [
        _mock_response(200, {"id": "actor-1", "name": "APT42"}),
        _mock_response(200, {"id": "mal-1", "name": "Emotet"}),
    ]
    connector = MandiantConnector(access_token="tok-abc", session=session)
    actor = connector.fetch_actor("actor-1")
    malware = connector.fetch_malware("mal-1")
    assert actor == {"id": "actor-1", "name": "APT42"}
    assert malware == {"id": "mal-1", "name": "Emotet"}
    urls = [c.args[1] for c in session.request.call_args_list]
    assert any(u.endswith("/actor/actor-1") for u in urls)
    assert any(u.endswith("/malware/mal-1") for u in urls)


# ---------------------------------------------------------------------------
# Error / rate-limit handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.request.side_effect = [
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_INDICATORS),
    ]
    connector = MandiantConnector(
        access_token="tok-abc",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    assert len(connector.fetch({})) == 3
    assert session.request.call_count == 2
    assert len(sleeps) == 1


@pytest.mark.unit
def test_fetch_returns_empty_on_5xx():
    session = MagicMock()
    session.request.return_value = _mock_response(503, {})
    connector = MandiantConnector(
        access_token="tok-abc",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_returns_empty_on_network_error():
    session = MagicMock()
    session.request.side_effect = requests.ConnectionError("boom")
    connector = MandiantConnector(
        access_token="tok-abc",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch({}) == []


@pytest.mark.unit
def test_fetch_returns_empty_on_bad_json():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("nope")
    resp.text = "oops"
    session = MagicMock()
    session.request.return_value = resp
    connector = MandiantConnector(access_token="tok-abc", session=session)
    assert connector.fetch({}) == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_mandiant_registered():
    assert "mandiant" in get_registered_ioc_connectors()
    assert get_ioc_connector("mandiant") is MandiantConnector
