"""Vendor advisory feed connector -- routes raw vendor data through registered parsers."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.vendor_advisory_client import (
    VendorAdvisoryRegistry,
    default_registry,
    validate_normalized,
)
from app.models.sheshnaag import AdvisoryRecord, ProductRecord

logger = logging.getLogger(__name__)


@register_connector
class VendorAdvisoryConnector(FeedConnector):
    name = "vendor_advisory"
    display_name = "Vendor Advisories"
    category = "vendor"
    source_url = ""
    supports_cursor = False
    default_freshness_seconds = 21600

    def __init__(self, registry: Optional[VendorAdvisoryRegistry] = None) -> None:
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
        """Ingest vendor advisory data through registered parsers.

        *raw_batches* maps vendor names to lists of raw payloads, e.g.::

            {"example_vendor": [payload1, payload2]}

        Each payload is handed to the matching ``VendorAdvisoryParser.parse``
        method.  The connector does **not** commit -- the caller manages the
        transaction.
        """
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        if not raw_batches:
            result.completed_at = utc_now().isoformat()
            return result

        for vendor_name, payloads in raw_batches.items():
            parser = self._registry.get(vendor_name)
            if parser is None:
                logger.warning("No parser registered for vendor %r -- skipping", vendor_name)
                result.errors.append({"vendor": vendor_name, "error": "no parser registered"})
                continue

            for raw in payloads:
                try:
                    advisories = parser.parse(raw)
                    result.items_fetched += len(advisories)

                    for adv in advisories:
                        validate_normalized(adv)
                        self._persist(session, adv)
                        result.items_new += 1
                except Exception as exc:
                    result.errors.append({"vendor": vendor_name, "error": str(exc)})

        result.completed_at = utc_now().isoformat()
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _persist(session: Session, adv: dict) -> None:
        """Map a normalized advisory dict into ORM rows."""
        product = None
        for ap in adv.get("affected_products", []):
            existing = (
                session.query(ProductRecord)
                .filter(
                    ProductRecord.vendor == adv["vendor"],
                    ProductRecord.name == ap["name"],
                )
                .first()
            )
            if existing is None:
                product = ProductRecord(
                    vendor=adv["vendor"],
                    name=ap["name"],
                    meta={"version_hint": ap.get("version_hint", "")},
                )
                session.add(product)
                session.flush()
            else:
                product = existing

        record = AdvisoryRecord(
            external_id=adv["advisory_id"],
            title=adv["title"],
            summary=adv.get("summary", ""),
            source_url=adv.get("source_url", ""),
            published_at=adv.get("published_at"),
            raw_data=adv.get("raw_data", {}),
            product_id=product.id if product else None,
        )
        session.add(record)
