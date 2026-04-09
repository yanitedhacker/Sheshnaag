"""Tests for the GHSA (GitHub Advisory Database) connector."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.connector import get_registered_connectors
from app.ingestion.ghsa_client import GHSAClient
from app.ingestion.ghsa_connector import GHSAConnector
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryPackageLink, AdvisoryRecord, PackageRecord, VersionRange


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


SAMPLE_GHSA_ADVISORY = {
    "ghsa_id": "GHSA-abcd-1234-efgh",
    "cve_id": "CVE-2024-99999",
    "summary": "Example vulnerability in test-pkg",
    "description": "A serious vulnerability was found in test-pkg allowing RCE.",
    "severity": "high",
    "vulnerabilities": [
        {
            "package": {"ecosystem": "pip", "name": "test-pkg"},
            "vulnerable_version_range": ">= 1.0, < 1.5.3",
        },
        {
            "package": {"ecosystem": "npm", "name": "test-js-pkg"},
            "vulnerable_version_range": "< 2.0.0",
        },
    ],
    "references": [
        {"url": "https://github.com/advisories/GHSA-abcd-1234-efgh"},
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-99999"},
    ],
    "published_at": "2024-06-15T10:00:00Z",
    "updated_at": "2024-06-16T12:00:00Z",
}

SAMPLE_GHSA_NO_CVE = {
    "ghsa_id": "GHSA-zzzz-9999-yyyy",
    "cve_id": None,
    "summary": "Advisory without CVE mapping",
    "description": "This advisory has no associated CVE identifier.",
    "severity": "medium",
    "vulnerabilities": [
        {
            "package": {"ecosystem": "go", "name": "example.com/vulnerable"},
            "vulnerable_version_range": "< 0.3.1",
        },
    ],
    "references": [],
    "published_at": "2024-07-01T08:30:00Z",
    "updated_at": "2024-07-01T08:30:00Z",
}


@pytest.mark.unit
def test_parse_ghsa_advisory_with_cve():
    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_ADVISORY)

    assert parsed["ghsa_id"] == "GHSA-ABCD-1234-EFGH"
    assert parsed["cve_id"] == "CVE-2024-99999"
    assert parsed["severity"] == "high"
    assert len(parsed["packages"]) == 2
    assert parsed["packages"][0]["ecosystem"] == "pypi"
    assert parsed["packages"][0]["name"] == "test-pkg"
    assert len(parsed["version_ranges"]) == 2
    assert len(parsed["references"]) == 2
    assert parsed["canonical_id"] == "CVE-2024-99999"
    assert parsed["payload_hash"]


@pytest.mark.unit
def test_parse_ghsa_advisory_without_cve():
    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_NO_CVE)

    assert parsed["ghsa_id"] == "GHSA-ZZZZ-9999-YYYY"
    assert parsed["cve_id"] is None
    assert parsed["severity"] == "medium"
    assert len(parsed["packages"]) == 1
    assert parsed["packages"][0]["ecosystem"] == "go"


@pytest.mark.unit
def test_save_advisory_creates_advisory_and_packages():
    session = _make_session()
    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_ADVISORY)

    is_new, advisory = client.save_advisory_to_db(session, parsed)
    session.flush()

    assert is_new is True
    assert advisory.external_id == "GHSA-ABCD-1234-EFGH"
    assert advisory.title == "Example vulnerability in test-pkg"
    assert advisory.cve_id is None  # CVE row doesn't exist in this DB

    pkgs = session.query(PackageRecord).all()
    assert len(pkgs) == 2
    ecosystems = {p.ecosystem for p in pkgs}
    assert ecosystems == {"pypi", "npm"}
    assert session.query(AdvisoryPackageLink).count() == 2
    assert session.query(VersionRange).count() == 2


@pytest.mark.unit
def test_save_advisory_links_to_existing_cve():
    session = _make_session()

    cve = CVE(cve_id="CVE-2024-99999", description="Test CVE")
    session.add(cve)
    session.flush()

    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_ADVISORY)
    is_new, advisory = client.save_advisory_to_db(session, parsed)
    session.flush()

    assert is_new is True
    assert advisory.cve_id == cve.id


@pytest.mark.unit
def test_save_advisory_without_cve_remains_queryable():
    session = _make_session()
    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_NO_CVE)

    is_new, advisory = client.save_advisory_to_db(session, parsed)
    session.flush()

    assert is_new is True
    assert advisory.cve_id is None

    found = (
        session.query(AdvisoryRecord)
        .filter(AdvisoryRecord.external_id == "GHSA-ZZZZ-9999-YYYY")
        .first()
    )
    assert found is not None
    assert found.title == "Advisory without CVE mapping"


@pytest.mark.unit
def test_duplicate_advisory_updates_instead_of_inserting():
    session = _make_session()
    client = GHSAClient(token="fake")
    parsed = client.parse_advisory(SAMPLE_GHSA_ADVISORY)

    is_new_1, adv1 = client.save_advisory_to_db(session, parsed)
    session.flush()
    assert is_new_1 is True

    is_new_2, adv2 = client.save_advisory_to_db(session, parsed)
    session.flush()
    assert is_new_2 is False

    count = session.query(AdvisoryRecord).filter(
        AdvisoryRecord.external_id == "GHSA-ABCD-1234-EFGH"
    ).count()
    assert count == 1


@pytest.mark.unit
def test_ghsa_connector_is_registered():
    connectors = get_registered_connectors()
    assert "ghsa" in connectors
    assert connectors["ghsa"] is GHSAConnector


@pytest.mark.unit
def test_ghsa_connector_metadata():
    connector = GHSAConnector()
    assert connector.name == "ghsa"
    assert connector.display_name == "GitHub Advisory Database"
    assert connector.category == "package"
    assert connector.supports_cursor is True


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ghsa_connector_fetch_end_to_end():
    session = _make_session()

    cve = CVE(cve_id="CVE-2024-99999", description="Test CVE")
    session.add(cve)
    session.flush()

    connector = GHSAConnector()
    mock_response = [SAMPLE_GHSA_ADVISORY, SAMPLE_GHSA_NO_CVE]

    with patch.object(
        connector._client, "fetch_advisories", new_callable=AsyncMock, return_value=mock_response
    ):
        result = await connector.fetch(session, limit=100)

    assert result.source == "ghsa"
    assert result.items_fetched == 2
    assert result.items_new == 2
    assert result.items_updated == 0
    assert result.errors == []
    assert result.started_at is not None
    assert result.completed_at is not None
    assert result.cursor is not None

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 2


@pytest.mark.unit
def test_normalize_ghsa_id():
    assert GHSAClient.normalize_ghsa_id("  ghsa-abcd-1234-efgh  ") == "GHSA-ABCD-1234-EFGH"
    assert GHSAClient.normalize_ghsa_id("GHSA-XXXX-YYYY-ZZZZ") == "GHSA-XXXX-YYYY-ZZZZ"
