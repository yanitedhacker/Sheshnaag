"""Patch note feed connector -- routes raw release/changelog data through registered parsers."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.patch_note_client import (
    PatchNoteRegistry,
    default_registry,
    validate_patch_note,
)
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryRecord, PackageRecord, ProductRecord

logger = logging.getLogger(__name__)


@register_connector
class PatchNoteConnector(FeedConnector):
    name = "patch_notes"
    display_name = "Patch Notes"
    category = "vendor"
    source_url = ""
    supports_cursor = False
    default_freshness_seconds = 21600

    def __init__(self, registry: Optional[PatchNoteRegistry] = None) -> None:
        self._registry = registry or default_registry

    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
        raw_batches: Optional[dict] = None,
    ) -> ConnectorResult:
        """Ingest patch note data through registered parsers.

        *raw_batches* maps source names to lists of raw payloads, e.g.::

            {"example_patch_source": [payload1, payload2]}

        Each payload is handed to the matching ``PatchNoteParser.parse``
        method.  The connector does **not** commit -- the caller manages the
        transaction.
        """
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        if not raw_batches:
            result.completed_at = utc_now().isoformat()
            return result

        for source_name, payloads in raw_batches.items():
            parser = self._registry.get(source_name)
            if parser is None:
                logger.warning("No parser registered for source %r -- skipping", source_name)
                result.errors.append({"source": source_name, "error": "no parser registered"})
                continue

            for raw in payloads:
                try:
                    notes = parser.parse(raw)
                    result.items_fetched += len(notes)

                    for note in notes:
                        validate_patch_note(note)
                        self._persist(session, note)
                        result.items_new += 1
                except Exception as exc:
                    result.errors.append({"source": source_name, "error": str(exc)})

        result.completed_at = utc_now().isoformat()
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _persist(session: Session, note: dict) -> None:
        """Map a normalized patch note dict into ORM rows."""

        # -- Product -------------------------------------------------------
        product = None
        if note.get("product_name"):
            existing_product = (
                session.query(ProductRecord)
                .filter(
                    ProductRecord.vendor == note["source"],
                    ProductRecord.name == note["product_name"],
                )
                .first()
            )
            if existing_product is None:
                product = ProductRecord(
                    vendor=note["source"],
                    name=note["product_name"],
                    meta={"version": note.get("product_version", "")},
                )
                session.add(product)
                session.flush()
            else:
                product = existing_product

        # -- Package records -----------------------------------------------
        for hint in note.get("package_hints", []):
            existing_pkg = (
                session.query(PackageRecord)
                .filter(
                    PackageRecord.ecosystem == hint["ecosystem"],
                    PackageRecord.name == hint["name"],
                )
                .first()
            )
            if existing_pkg is None:
                pkg = PackageRecord(
                    ecosystem=hint["ecosystem"],
                    name=hint["name"],
                    meta={"from_patch_note": note["note_id"]},
                )
                session.add(pkg)

        # -- CVE linking ---------------------------------------------------
        cve_row = None
        for cve_id_str in note.get("cve_ids", []):
            matched = (
                session.query(CVE)
                .filter(CVE.cve_id == cve_id_str)
                .first()
            )
            if matched is not None:
                cve_row = matched

        # -- Advisory record -----------------------------------------------
        raw_data = note.get("raw_data", {})
        raw_data["_advisory_type"] = "patch_note"
        raw_data["_cve_ids"] = note.get("cve_ids", [])
        raw_data["_package_hints"] = note.get("package_hints", [])
        raw_data["_product_version"] = note.get("product_version")
        raw_data["_provenance"] = {
            "has_product": note.get("product_name") is not None,
            "has_cve": bool(note.get("cve_ids")),
            "has_packages": bool(note.get("package_hints")),
            "linked_cve_found": cve_row is not None,
        }

        record = AdvisoryRecord(
            external_id=note["note_id"],
            title=note["title"],
            summary=note.get("summary", ""),
            source_url=note.get("source_url", ""),
            published_at=note.get("published_at"),
            raw_data=raw_data,
            product_id=product.id if product else None,
            cve_id=cve_row.id if cve_row else None,
        )
        session.add(record)
