"""FIRST EPSS feed connector -- wraps EPSSClient behind FeedConnector protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.epss_client import EPSSClient
from app.models.v2 import EPSSSnapshot


@register_connector
class EPSSConnector(FeedConnector):
    name = "epss"
    display_name = "FIRST EPSS"
    category = "exploitability"
    source_url = "https://www.first.org/epss/"
    supports_cursor = True
    default_freshness_seconds = 86400  # daily feed

    def __init__(self) -> None:
        self._client = EPSSClient()

    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
    ) -> ConnectorResult:
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        now = utc_now()
        raw_rows = await self._client.fetch_all_scores()
        parsed = self._client.parse_scores(raw_rows, scored_at=now)
        result.items_fetched = len(parsed)

        for entry in parsed:
            try:
                cve_id = entry["cve_id"]
                scored_at = entry["scored_at"]
                raw_hash = self.hash_payload(entry["raw"])

                existing = (
                    session.query(EPSSSnapshot)
                    .filter(
                        EPSSSnapshot.cve_id == cve_id,
                        EPSSSnapshot.scored_at == scored_at,
                    )
                    .first()
                )

                if existing:
                    existing.score = entry["score"]
                    existing.percentile = entry["percentile"]
                    existing.raw_data = entry["raw"]
                    result.items_updated += 1
                else:
                    session.add(
                        EPSSSnapshot(
                            cve_id=cve_id,
                            score=entry["score"],
                            percentile=entry["percentile"],
                            scored_at=scored_at,
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
