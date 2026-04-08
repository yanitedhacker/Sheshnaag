"""CISA KEV feed connector -- wraps KEVClient behind FeedConnector protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.kev_client import KEVClient
from app.models.v2 import KEVEntry


@register_connector
class KEVConnector(FeedConnector):
    name = "kev"
    display_name = "CISA KEV"
    category = "exploitability"
    source_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    supports_cursor = True
    default_freshness_seconds = 21600

    def __init__(self) -> None:
        self._client = KEVClient()

    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
    ) -> ConnectorResult:
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        catalog = await self._client.fetch_catalog()
        parsed = self._client.parse_vulnerabilities(catalog)
        result.items_fetched = len(parsed)

        for entry in parsed:
            try:
                cve_id = entry["cve_id"]
                if not cve_id:
                    continue

                raw_hash = self.hash_payload(entry["raw"])

                existing = (
                    session.query(KEVEntry).filter(KEVEntry.cve_id == cve_id).first()
                )

                if existing:
                    existing.vendor_project = entry["vendor_project"]
                    existing.product = entry["product"]
                    existing.short_description = entry["short_description"]
                    existing.added_date = entry["date_added"]
                    existing.due_date = entry["due_date"]
                    existing.known_ransomware_use = entry[
                        "known_ransomware_campaign_use"
                    ]
                    existing.source_url = self.source_url
                    existing.raw_data = entry["raw"]
                    result.items_updated += 1
                else:
                    session.add(
                        KEVEntry(
                            cve_id=cve_id,
                            vendor_project=entry["vendor_project"],
                            product=entry["product"],
                            short_description=entry["short_description"],
                            added_date=entry["date_added"],
                            due_date=entry["due_date"],
                            known_ransomware_use=entry[
                                "known_ransomware_campaign_use"
                            ],
                            source_url=self.source_url,
                            raw_data=entry["raw"],
                        )
                    )
                    result.items_new += 1
            except Exception as exc:
                result.errors.append(
                    {"cve_id": entry.get("cve_id", "unknown"), "error": str(exc)}
                )

        result.completed_at = utc_now().isoformat()
        result.cursor = utc_now().isoformat()
        return result
