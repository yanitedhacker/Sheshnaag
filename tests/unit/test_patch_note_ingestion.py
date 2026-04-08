"""Unit tests for patch note ingestion framework (WS1-T7)."""

from __future__ import annotations

import asyncio
from typing import List

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.ingestion.patch_note_client import (
    EXAMPLE_PATCH_NOTE_FIXTURE,
    ExamplePatchNoteParser,
    NormalizedPatchNote,
    PatchNoteParser,
    PatchNoteRegistry,
    validate_patch_note,
)
from app.ingestion.patch_note_connector import PatchNoteConnector
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryRecord, PackageRecord, ProductRecord


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
    reg = PatchNoteRegistry()
    parser = ExamplePatchNoteParser()
    reg.register(parser)

    assert reg.get("example_patch_source") is parser
    assert reg.get("nonexistent") is None


@pytest.mark.unit
def test_registry_all_parsers():
    reg = PatchNoteRegistry()
    p1 = ExamplePatchNoteParser()
    reg.register(p1)

    all_p = reg.all_parsers()
    assert "example_patch_source" in all_p
    assert all_p["example_patch_source"] is p1


# ---------------------------------------------------------------------------
# ExamplePatchNoteParser
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_example_parser_produces_valid_normalized_data():
    parser = ExamplePatchNoteParser()
    results = parser.parse(EXAMPLE_PATCH_NOTE_FIXTURE)

    assert len(results) == 1
    note = results[0]

    assert note["source"] == "example_patch_source"
    assert note["note_id"] == "PN-2025-042"
    assert note["title"] == "Acme Firewall v3.2.1 Security Patch"
    assert note["source_url"].startswith("https://")
    assert note["published_at"] is not None
    assert note["product_name"] == "Acme Firewall"
    assert note["product_version"] == "3.2.1"
    assert note["cve_ids"] == ["CVE-2025-11111", "CVE-2025-22222"]
    assert len(note["package_hints"]) == 1
    assert note["package_hints"][0] == {"ecosystem": "deb", "name": "acme-firewall"}
    assert note["raw_data"] == EXAMPLE_PATCH_NOTE_FIXTURE

    validate_patch_note(note)


@pytest.mark.unit
def test_validate_patch_note_rejects_incomplete():
    with pytest.raises(ValueError, match="missing required fields"):
        validate_patch_note({"source": "x"})


# ---------------------------------------------------------------------------
# Connector persists AdvisoryRecord rows
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_connector_persists_advisory_records():
    reg = PatchNoteRegistry()
    reg.register(ExamplePatchNoteParser())

    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"example_patch_source": [EXAMPLE_PATCH_NOTE_FIXTURE]},
        )
    )

    session.flush()

    assert result.items_fetched == 1
    assert result.items_new == 1
    assert result.errors == []

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 1
    assert advisories[0].external_id == "PN-2025-042"
    assert advisories[0].title == "Acme Firewall v3.2.1 Security Patch"
    assert advisories[0].source_url == "https://acme.example.com/releases/3.2.1"
    assert advisories[0].published_at is not None
    assert advisories[0].raw_data["_advisory_type"] == "patch_note"

    products = session.query(ProductRecord).all()
    assert len(products) == 1
    assert products[0].vendor == "example_patch_source"
    assert products[0].name == "Acme Firewall"

    packages = session.query(PackageRecord).all()
    assert len(packages) == 1
    assert packages[0].ecosystem == "deb"
    assert packages[0].name == "acme-firewall"


@pytest.mark.unit
def test_connector_handles_missing_parser_gracefully():
    reg = PatchNoteRegistry()
    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"unknown_source": [{"some": "data"}]},
        )
    )

    assert result.items_fetched == 0
    assert len(result.errors) == 1
    assert result.errors[0]["source"] == "unknown_source"


# ---------------------------------------------------------------------------
# Incomplete mapping scenarios
# ---------------------------------------------------------------------------


class _MinimalParser(PatchNoteParser):
    """Parser that produces notes with no CVE, no product, no packages."""

    def source_name(self) -> str:
        return "minimal_source"

    def parse(self, raw_data: dict) -> List[NormalizedPatchNote]:
        return [
            {
                "source": self.source_name(),
                "note_id": raw_data["id"],
                "title": raw_data["title"],
                "summary": raw_data.get("summary", ""),
                "source_url": raw_data.get("url", ""),
                "published_at": None,
                "product_name": None,
                "product_version": None,
                "cve_ids": [],
                "package_hints": [],
                "raw_data": raw_data,
            }
        ]


@pytest.mark.unit
def test_note_with_no_cve_no_product_persists():
    """A patch note with no CVE, no product, and no packages still persists."""
    reg = PatchNoteRegistry()
    reg.register(_MinimalParser())

    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    payload = {"id": "MIN-001", "title": "Minimal Note", "url": "https://example.com/min"}

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"minimal_source": [payload]},
        )
    )

    session.flush()

    assert result.items_fetched == 1
    assert result.items_new == 1
    assert result.errors == []

    advisories = session.query(AdvisoryRecord).all()
    assert len(advisories) == 1
    assert advisories[0].external_id == "MIN-001"
    assert advisories[0].product_id is None
    assert advisories[0].cve_id is None

    provenance = advisories[0].raw_data["_provenance"]
    assert provenance["has_product"] is False
    assert provenance["has_cve"] is False
    assert provenance["has_packages"] is False
    assert provenance["linked_cve_found"] is False

    assert session.query(ProductRecord).count() == 0
    assert session.query(PackageRecord).count() == 0


@pytest.mark.unit
def test_note_links_to_existing_cve():
    """When a CVE exists in the DB, the advisory row should link to it."""
    reg = PatchNoteRegistry()
    reg.register(ExamplePatchNoteParser())

    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    cve = CVE(cve_id="CVE-2025-11111", description="Test CVE")
    session.add(cve)
    session.flush()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"example_patch_source": [EXAMPLE_PATCH_NOTE_FIXTURE]},
        )
    )

    session.flush()

    assert result.items_new == 1
    advisory = session.query(AdvisoryRecord).first()
    assert advisory.cve_id == cve.id
    assert advisory.raw_data["_provenance"]["linked_cve_found"] is True


@pytest.mark.unit
def test_note_with_cve_ids_but_no_match():
    """CVE IDs in the note but none in DB -- advisory persists without link."""
    reg = PatchNoteRegistry()
    reg.register(ExamplePatchNoteParser())

    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(
        connector.fetch(
            session,
            raw_batches={"example_patch_source": [EXAMPLE_PATCH_NOTE_FIXTURE]},
        )
    )

    session.flush()

    advisory = session.query(AdvisoryRecord).first()
    assert advisory.cve_id is None
    assert advisory.raw_data["_provenance"]["has_cve"] is True
    assert advisory.raw_data["_provenance"]["linked_cve_found"] is False


@pytest.mark.unit
def test_empty_raw_batches_returns_early():
    reg = PatchNoteRegistry()
    connector = PatchNoteConnector(registry=reg)
    session = _make_session()

    result = asyncio.run(connector.fetch(session, raw_batches=None))

    assert result.items_fetched == 0
    assert result.items_new == 0
    assert result.errors == []
    assert result.completed_at is not None
