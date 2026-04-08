"""Unit tests for the OSV connector."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.connector import get_registered_connectors
from app.ingestion.osv_client import OSVClient
from app.ingestion.osv_connector import OSVConnector
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryRecord, PackageRecord, VersionRange


SAMPLE_OSV_VULN = {
    "id": "GHSA-test-0001",
    "summary": "Test vulnerability in example-pkg",
    "details": "A detailed description of the vulnerability.",
    "aliases": ["CVE-2024-99999"],
    "published": "2024-06-01T00:00:00Z",
    "modified": "2024-06-02T12:00:00Z",
    "affected": [
        {
            "package": {
                "ecosystem": "PyPI",
                "name": "example-pkg",
                "purl": "pkg:pypi/example-pkg",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.2.3"},
                    ],
                }
            ],
        }
    ],
    "references": [
        {"type": "ADVISORY", "url": "https://example.com/advisory"},
    ],
}

SAMPLE_OSV_VULN_NO_CVE = {
    "id": "GHSA-test-0002",
    "summary": "Another test vuln",
    "details": "",
    "aliases": [],
    "published": "2024-07-01T00:00:00Z",
    "modified": "2024-07-02T00:00:00Z",
    "affected": [
        {
            "package": {
                "ecosystem": "npm",
                "name": "some-npm-pkg",
                "purl": "pkg:npm/some-npm-pkg",
            },
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"last_affected": "2.0.0"},
                    ],
                }
            ],
        }
    ],
    "references": [],
}


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return testing_session_local()


@pytest.mark.unit
def test_parse_advisory_basic():
    parsed = OSVClient.parse_advisory(SAMPLE_OSV_VULN)

    assert parsed["osv_id"] == "GHSA-test-0001"
    assert parsed["summary"] == "Test vulnerability in example-pkg"
    assert parsed["cve_aliases"] == ["CVE-2024-99999"]
    assert len(parsed["packages"]) == 1
    assert parsed["packages"][0]["ecosystem"] == "PyPI"
    assert parsed["packages"][0]["name"] == "example-pkg"
    assert len(parsed["version_ranges"]) == 1
    assert parsed["version_ranges"][0]["fixed_version"] == "1.2.3"
    assert parsed["raw"] is SAMPLE_OSV_VULN


@pytest.mark.unit
def test_parse_advisory_no_cve():
    parsed = OSVClient.parse_advisory(SAMPLE_OSV_VULN_NO_CVE)

    assert parsed["osv_id"] == "GHSA-test-0002"
    assert parsed["cve_aliases"] == []
    assert parsed["version_ranges"][0]["version_end"] == "2.0.0"
    assert parsed["version_ranges"][0]["fixed_version"] == ""


@pytest.mark.unit
@pytest.mark.asyncio
async def test_connector_fetch_creates_advisory_and_package():
    session = _make_session()
    connector = OSVConnector()

    with patch.object(
        connector._client,
        "fetch_recent",
        new_callable=AsyncMock,
        return_value=[SAMPLE_OSV_VULN],
    ):
        result = await connector.fetch(session, limit=10)

    session.flush()

    assert result.items_fetched == 1
    assert result.items_new == 1
    assert result.items_updated == 0

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 1
    assert advisories[0].external_id == "GHSA-test-0001"
    assert advisories[0].title == "Test vulnerability in example-pkg"

    packages = session.query(PackageRecord).all()
    assert len(packages) == 1
    assert packages[0].ecosystem == "PyPI"
    assert packages[0].name == "example-pkg"

    vrs = session.query(VersionRange).all()
    assert len(vrs) == 1
    assert vrs[0].fixed_version == "1.2.3"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_connector_links_cve_when_alias_exists():
    session = _make_session()

    cve = CVE(cve_id="CVE-2024-99999", description="pre-existing CVE")
    session.add(cve)
    session.flush()

    connector = OSVConnector()
    with patch.object(
        connector._client,
        "fetch_recent",
        new_callable=AsyncMock,
        return_value=[SAMPLE_OSV_VULN],
    ):
        result = await connector.fetch(session, limit=10)

    session.flush()

    advisory = session.query(AdvisoryRecord).first()
    assert advisory is not None
    assert advisory.cve_id == cve.id


@pytest.mark.unit
@pytest.mark.asyncio
async def test_duplicate_advisory_updates_instead_of_creating():
    session = _make_session()
    connector = OSVConnector()

    with patch.object(
        connector._client,
        "fetch_recent",
        new_callable=AsyncMock,
        return_value=[SAMPLE_OSV_VULN],
    ):
        r1 = await connector.fetch(session, limit=10)
        r2 = await connector.fetch(session, limit=10)

    session.flush()

    assert r1.items_new == 1
    assert r2.items_updated == 1
    assert r2.items_new == 0

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_duplicate_package_not_created():
    """Two advisories sharing the same ecosystem+name reuse one PackageRecord."""
    session = _make_session()

    vuln2 = {
        **SAMPLE_OSV_VULN_NO_CVE,
        "id": "GHSA-test-0003",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "example-pkg",
                    "purl": "pkg:pypi/example-pkg",
                },
                "ranges": [],
            }
        ],
    }

    connector = OSVConnector()
    with patch.object(
        connector._client,
        "fetch_recent",
        new_callable=AsyncMock,
        return_value=[SAMPLE_OSV_VULN, vuln2],
    ):
        await connector.fetch(session, limit=10)

    session.flush()

    packages = session.query(PackageRecord).filter(
        PackageRecord.ecosystem == "PyPI",
        PackageRecord.name == "example-pkg",
    ).all()
    assert len(packages) == 1


@pytest.mark.unit
def test_osv_connector_is_registered():
    connectors = get_registered_connectors()
    assert "osv" in connectors
    assert connectors["osv"] is OSVConnector
