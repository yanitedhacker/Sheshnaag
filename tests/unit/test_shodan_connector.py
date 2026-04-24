"""Unit tests for the Shodan IOC connector."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from app.ingestion.misp_connector import (
    get_ioc_connector,
    get_registered_ioc_connectors,
)
from app.ingestion.shodan_connector import ShodanConnector


SAMPLE_HOST = {
    "ip_str": "198.51.100.7",
    "ports": [22, 80, 443, 8080],
    "hostnames": ["web.example", "mail.example"],
    "tags": ["cloud"],
    "vulns": {
        "CVE-2023-1234": {"cvss": 8.8},
        "CVE-2024-5678": {"cvss": 7.5},
    },
    "org": "Example Corp",
    "isp": "Example ISP",
    "asn": "AS64500",
    "country_code": "US",
    "os": "Linux 4.x",
    "last_update": "2024-02-15T00:00:00Z",
}


SAMPLE_SEARCH = {
    "matches": [
        {
            "ip_str": "203.0.113.1",
            "port": 22,
            "hostnames": ["a.example"],
            "product": "OpenSSH",
            "org": "OrgA",
            "asn": "AS1",
            "timestamp": "2024-02-10T00:00:00",
            "location": {"country_code": "US"},
            "tags": [],
        },
        {
            "ip_str": "203.0.113.2",
            "port": 443,
            "hostnames": [],
            "product": "nginx",
            "org": "OrgB",
            "timestamp": "2024-02-11T00:00:00",
        },
    ],
    "total": 2,
}


SAMPLE_DNS = {
    "domain": "example.com",
    "tags": ["phishing"],
    "data": [
        {
            "subdomain": "",
            "type": "A",
            "value": "93.184.216.34",
            "first_seen": "2024-01-01T00:00:00",
            "last_seen": "2024-02-15T00:00:00",
        },
        {
            "subdomain": "mail",
            "type": "CNAME",
            "value": "mail.google.com",
            "last_seen": "2024-02-14T00:00:00",
        },
        {
            "subdomain": "",
            "type": "MX",
            "value": "mx1.example.com",
        },
    ],
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
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert ShodanConnector().healthy is False


@pytest.mark.unit
def test_health_true_with_env(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    assert ShodanConnector().healthy is True


# ---------------------------------------------------------------------------
# Fetch -- env missing
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_returns_empty_without_env(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    session = MagicMock()
    connector = ShodanConnector(session=session)
    assert connector.fetch({"hosts": ["1.1.1.1"]}) == []
    session.get.assert_not_called()


@pytest.mark.unit
def test_fetch_host_returns_none_without_env(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    session = MagicMock()
    connector = ShodanConnector(session=session)
    assert connector.fetch_host("1.2.3.4") is None
    session.get.assert_not_called()


# ---------------------------------------------------------------------------
# fetch_host
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_host_normalizes():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_HOST)
    connector = ShodanConnector(api_key="shodan-key", session=session)

    record = connector.fetch_host("198.51.100.7")

    assert record is not None
    assert record["source"] == "shodan"
    assert record["indicator_kind"] == "ip"
    assert record["value"] == "198.51.100.7"
    assert record["confidence"] > 0.3
    assert record["payload"]["ports"] == [22, 80, 443, 8080]
    assert record["payload"]["hostnames"] == ["web.example", "mail.example"]
    assert "CVE-2023-1234" in record["payload"]["vulns"]
    assert "CVE-2023-1234" in record["tags"]
    assert "Example Corp" in record["labels"]
    assert "US" in record["labels"]

    call = session.get.call_args
    assert call.args[0].endswith("/shodan/host/198.51.100.7")
    assert call.kwargs["params"]["key"] == "shodan-key"


# ---------------------------------------------------------------------------
# fetch_search
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_search_normalizes():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_SEARCH)
    connector = ShodanConnector(api_key="shodan-key", session=session)

    records = connector.fetch_search("apache country:US", limit=10)

    assert len(records) == 2
    assert records[0]["source"] == "shodan"
    assert records[0]["indicator_kind"] == "ip"
    assert records[0]["value"] == "203.0.113.1"
    assert "OpenSSH" in records[0]["labels"]
    assert "OrgA" in records[0]["labels"]
    assert records[0]["payload"]["port"] == 22

    call = session.get.call_args
    assert call.args[0].endswith("/shodan/host/search")
    assert call.kwargs["params"]["query"] == "apache country:US"
    assert call.kwargs["params"]["limit"] == 10
    assert call.kwargs["params"]["key"] == "shodan-key"


# ---------------------------------------------------------------------------
# fetch_dns
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_dns_normalizes():
    session = MagicMock()
    session.get.return_value = _mock_response(200, SAMPLE_DNS)
    connector = ShodanConnector(api_key="shodan-key", session=session)

    records = connector.fetch_dns("example.com")

    assert len(records) == 3
    a_row = next(r for r in records if r["payload"]["record_type"] == "A")
    assert a_row["indicator_kind"] == "ip"
    assert a_row["value"] == "93.184.216.34"
    assert "A" in a_row["tags"]

    cname_row = next(r for r in records if r["payload"]["record_type"] == "CNAME")
    assert cname_row["indicator_kind"] == "domain"
    assert cname_row["value"] == "mail.google.com"
    assert cname_row["payload"]["subdomain"] == "mail"

    mx_row = next(r for r in records if r["payload"]["record_type"] == "MX")
    assert mx_row["indicator_kind"] == "domain"

    call = session.get.call_args
    assert call.args[0].endswith("/dns/domain/example.com")


# ---------------------------------------------------------------------------
# Generic fetch dispatches across kinds
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_fans_out_across_hosts_searches_domains():
    session = MagicMock()
    session.get.side_effect = [
        _mock_response(200, SAMPLE_HOST),
        _mock_response(200, SAMPLE_SEARCH),
        _mock_response(200, SAMPLE_DNS),
    ]
    connector = ShodanConnector(api_key="shodan-key", session=session)
    records = connector.fetch(
        {
            "hosts": ["198.51.100.7"],
            "searches": ["apache country:US"],
            "domains": ["example.com"],
            "limit": 5,
        }
    )
    # 1 host + 2 search matches + 3 DNS rows = 6
    assert len(records) == 6
    assert session.get.call_count == 3


# ---------------------------------------------------------------------------
# Error / rate-limit handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_fetch_host_retries_on_429_then_succeeds():
    sleeps: list[float] = []
    session = MagicMock()
    session.get.side_effect = [
        _mock_response(429, {}),
        _mock_response(429, {}),
        _mock_response(200, SAMPLE_HOST),
    ]
    connector = ShodanConnector(
        api_key="shodan-key",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=sleeps.append,
    )
    record = connector.fetch_host("198.51.100.7")
    assert record is not None
    assert session.get.call_count == 3
    assert len(sleeps) == 2


@pytest.mark.unit
def test_fetch_host_gives_up_after_persistent_429():
    session = MagicMock()
    session.get.return_value = _mock_response(429, {})
    connector = ShodanConnector(
        api_key="shodan-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_host("1.2.3.4") is None
    assert session.get.call_count == 2


@pytest.mark.unit
def test_fetch_host_404_returns_none():
    session = MagicMock()
    session.get.return_value = _mock_response(404, {})
    connector = ShodanConnector(
        api_key="shodan-key",
        session=session,
        max_retries=3,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_host("1.2.3.4") is None
    assert session.get.call_count == 1


@pytest.mark.unit
def test_fetch_returns_empty_on_5xx():
    session = MagicMock()
    session.get.return_value = _mock_response(503, {})
    connector = ShodanConnector(
        api_key="shodan-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_search("any", limit=5) == []


@pytest.mark.unit
def test_fetch_returns_empty_on_network_error():
    session = MagicMock()
    session.get.side_effect = requests.ConnectionError("boom")
    connector = ShodanConnector(
        api_key="shodan-key",
        session=session,
        max_retries=2,
        backoff_seconds=0.01,
        sleep_fn=lambda s: None,
    )
    assert connector.fetch_host("1.2.3.4") is None
    assert connector.fetch_dns("example.com") == []


@pytest.mark.unit
def test_fetch_returns_empty_on_bad_json():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("nope")
    resp.text = "oops"
    session = MagicMock()
    session.get.return_value = resp
    connector = ShodanConnector(api_key="shodan-key", session=session)
    assert connector.fetch_host("1.2.3.4") is None


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_shodan_registered():
    assert "shodan" in get_registered_ioc_connectors()
    assert get_ioc_connector("shodan") is ShodanConnector
