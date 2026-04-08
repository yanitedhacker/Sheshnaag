"""Unit tests for vendor advisory adapter framework (WS1-T6)."""

from __future__ import annotations

import asyncio
from typing import List

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.vendor_advisory_client import (
    EXAMPLE_FIXTURE,
    ExampleVendorParser,
    NormalizedAdvisory,
    VendorAdvisoryParser,
    VendorAdvisoryRegistry,
    validate_normalized,
)
from app.ingestion.vendor_advisory_connector import VendorAdvisoryConnector
from app.models.sheshnaag import AdvisoryRecord, ProductRecord


def _make_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_registry_register_and_lookup():
    reg = VendorAdvisoryRegistry()
    parser = ExampleVendorParser()
    reg.register(parser)

    assert reg.get("example_vendor") is parser
    assert reg.get("nonexistent") is None


@pytest.mark.unit
def test_registry_all_parsers():
    reg = VendorAdvisoryRegistry()
    p1 = ExampleVendorParser()
    reg.register(p1)

    all_p = reg.all_parsers()
    assert "example_vendor" in all_p
    assert all_p["example_vendor"] is p1


# ---------------------------------------------------------------------------
# ExampleVendorParser
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_example_parser_produces_valid_normalized_data():
    parser = ExampleVendorParser()
    results = parser.parse(EXAMPLE_FIXTURE)

    assert len(results) == 1
    adv = results[0]

    assert adv["vendor"] == "example_vendor"
    assert adv["advisory_id"] == "EX-2025-001"
    assert adv["title"] == "Example Widget RCE"
    assert adv["source_url"].startswith("https://")
    assert adv["published_at"] is not None
    assert adv["severity"] == "critical"
    assert len(adv["affected_products"]) == 1
    assert adv["affected_products"][0]["name"] == "Example Widget"
    assert adv["cve_ids"] == ["CVE-2025-99999"]
    assert adv["raw_data"] == EXAMPLE_FIXTURE

    validate_normalized(adv)


@pytest.mark.unit
def test_validate_normalized_rejects_incomplete():
    with pytest.raises(ValueError, match="missing required fields"):
        validate_normalized({"vendor": "x"})


# ---------------------------------------------------------------------------
# Connector persists AdvisoryRecord rows
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_connector_persists_advisory_records():
    reg = VendorAdvisoryRegistry()
    reg.register(ExampleVendorParser())

    connector = VendorAdvisoryConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"example_vendor": [EXAMPLE_FIXTURE]},
        )
    )

    session.flush()

    assert result.items_fetched == 1
    assert result.items_new == 1
    assert result.errors == []

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 1
    assert advisories[0].external_id == "EX-2025-001"
    assert advisories[0].title == "Example Widget RCE"
    assert advisories[0].source_url == "https://example.com/security/EX-2025-001"
    assert advisories[0].published_at is not None

    products = session.query(ProductRecord).all()
    assert len(products) == 1
    assert products[0].vendor == "example_vendor"
    assert products[0].name == "Example Widget"


@pytest.mark.unit
def test_connector_handles_missing_parser_gracefully():
    reg = VendorAdvisoryRegistry()
    connector = VendorAdvisoryConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"unknown_vendor": [{"some": "data"}]},
        )
    )

    assert result.items_fetched == 0
    assert len(result.errors) == 1
    assert result.errors[0]["vendor"] == "unknown_vendor"


# ---------------------------------------------------------------------------
# Extensibility: adding a new parser requires no connector changes
# ---------------------------------------------------------------------------


class _SecondVendorParser(VendorAdvisoryParser):
    def vendor_name(self) -> str:
        return "second_vendor"

    def parse(self, raw_data: dict) -> List[NormalizedAdvisory]:
        return [
            {
                "vendor": self.vendor_name(),
                "advisory_id": raw_data["id"],
                "title": raw_data["title"],
                "summary": raw_data.get("summary", ""),
                "source_url": raw_data.get("url", ""),
                "published_at": None,
                "severity": None,
                "affected_products": [],
                "cve_ids": [],
                "raw_data": raw_data,
            }
        ]


@pytest.mark.unit
def test_new_parser_works_without_connector_changes():
    reg = VendorAdvisoryRegistry()
    reg.register(ExampleVendorParser())
    reg.register(_SecondVendorParser())

    connector = VendorAdvisoryConnector(registry=reg)
    session = _make_session()

    second_payload = {"id": "SV-001", "title": "Second Vendor Bug", "url": "https://sv.test/001"}

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={
                "example_vendor": [EXAMPLE_FIXTURE],
                "second_vendor": [second_payload],
            },
        )
    )

    session.flush()

    assert result.items_fetched == 2
    assert result.items_new == 2
    assert result.errors == []

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 2
    ext_ids = {a.external_id for a in advisories}
    assert ext_ids == {"EX-2025-001", "SV-001"}
