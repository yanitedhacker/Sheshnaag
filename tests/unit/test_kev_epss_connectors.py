"""Unit tests for KEV and EPSS feed connectors."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.connector import get_registered_connectors
from app.ingestion.kev_client import KEVClient
from app.ingestion.kev_connector import KEVConnector
from app.ingestion.epss_client import EPSSClient
from app.ingestion.epss_connector import EPSSConnector
from app.models.v2 import EPSSSnapshot, KEVEntry


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)()


SAMPLE_KEV_CATALOG = {
    "title": "CISA KEV Catalog",
    "catalogVersion": "2024.01.01",
    "dateReleased": "2024-01-01T00:00:00Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1111",
            "vendorProject": "AcmeCorp",
            "product": "Widget",
            "vulnerabilityName": "Widget RCE",
            "dateAdded": "2024-06-01",
            "shortDescription": "Remote code execution in Widget.",
            "requiredAction": "Apply vendor update.",
            "dueDate": "2024-07-01",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2024-2222",
            "vendorProject": "FooCorp",
            "product": "Bar",
            "vulnerabilityName": "Bar Auth Bypass",
            "dateAdded": "2024-06-15",
            "shortDescription": "Authentication bypass.",
            "requiredAction": "Restrict access.",
            "dueDate": "2024-07-15",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


SAMPLE_EPSS_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "total": 2,
    "offset": 0,
    "limit": 1000,
    "data": [
        {"cve": "CVE-2024-1111", "epss": "0.97", "percentile": "0.995"},
        {"cve": "CVE-2024-2222", "epss": "0.42", "percentile": "0.75"},
    ],
}


# ---------------------------------------------------------------------------
# KEV client tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_kev_client_parses_catalog():
    client = KEVClient()
    parsed = client.parse_vulnerabilities(SAMPLE_KEV_CATALOG)

    assert len(parsed) == 2
    assert parsed[0]["cve_id"] == "CVE-2024-1111"
    assert parsed[0]["vendor_project"] == "AcmeCorp"
    assert parsed[0]["product"] == "Widget"
    assert parsed[0]["known_ransomware_campaign_use"] == "Known"
    assert isinstance(parsed[0]["date_added"], datetime)
    assert parsed[1]["cve_id"] == "CVE-2024-2222"


# ---------------------------------------------------------------------------
# KEV connector tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_kev_connector_persists_new_entries():
    session = _make_session()
    connector = KEVConnector()

    with patch.object(connector._client, "fetch_catalog", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = SAMPLE_KEV_CATALOG
        result = asyncio.run(connector.fetch(session))

    session.flush()

    assert result.source == "kev"
    assert result.items_fetched == 2
    assert result.items_new == 2
    assert result.items_updated == 0
    assert result.errors == []

    rows = session.query(KEVEntry).order_by(KEVEntry.cve_id).all()
    assert len(rows) == 2
    assert rows[0].cve_id == "CVE-2024-1111"
    assert rows[0].vendor_project == "AcmeCorp"
    assert rows[0].known_ransomware_use == "Known"
    assert rows[1].cve_id == "CVE-2024-2222"


@pytest.mark.unit
def test_kev_connector_upserts_existing_entries():
    session = _make_session()
    connector = KEVConnector()

    with patch.object(connector._client, "fetch_catalog", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = SAMPLE_KEV_CATALOG
        asyncio.run(connector.fetch(session))
        session.flush()

        updated_catalog = {
            **SAMPLE_KEV_CATALOG,
            "vulnerabilities": [
                {
                    **SAMPLE_KEV_CATALOG["vulnerabilities"][0],
                    "shortDescription": "Updated description.",
                },
            ],
        }
        mock_fetch.return_value = updated_catalog
        result = asyncio.run(connector.fetch(session))

    session.flush()
    assert result.items_updated == 1
    assert result.items_new == 0

    row = session.query(KEVEntry).filter(KEVEntry.cve_id == "CVE-2024-1111").first()
    assert row.short_description == "Updated description."


# ---------------------------------------------------------------------------
# EPSS client tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_epss_client_parses_scores():
    client = EPSSClient()
    scored_at = datetime(2024, 7, 1, tzinfo=timezone.utc)
    parsed = client.parse_scores(SAMPLE_EPSS_RESPONSE["data"], scored_at=scored_at)

    assert len(parsed) == 2
    assert parsed[0]["cve_id"] == "CVE-2024-1111"
    assert parsed[0]["score"] == pytest.approx(0.97)
    assert parsed[0]["percentile"] == pytest.approx(0.995)
    assert parsed[0]["scored_at"] == scored_at
    assert parsed[1]["cve_id"] == "CVE-2024-2222"


# ---------------------------------------------------------------------------
# EPSS connector tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_epss_connector_persists_new_snapshots():
    session = _make_session()
    connector = EPSSConnector()

    with patch.object(connector._client, "fetch_all_scores", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = SAMPLE_EPSS_RESPONSE["data"]
        result = asyncio.run(connector.fetch(session))

    session.flush()

    assert result.source == "epss"
    assert result.items_fetched == 2
    assert result.items_new == 2
    assert result.items_updated == 0
    assert result.errors == []

    rows = session.query(EPSSSnapshot).order_by(EPSSSnapshot.cve_id).all()
    assert len(rows) == 2
    assert rows[0].cve_id == "CVE-2024-1111"
    assert rows[0].score == pytest.approx(0.97)
    assert rows[1].cve_id == "CVE-2024-2222"


# ---------------------------------------------------------------------------
# Registry tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_kev_connector_registered():
    registry = get_registered_connectors()
    assert "kev" in registry
    assert registry["kev"] is KEVConnector


@pytest.mark.unit
def test_epss_connector_registered():
    registry = get_registered_connectors()
    assert "epss" in registry
    assert registry["epss"] is EPSSConnector
