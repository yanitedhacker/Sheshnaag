"""GHSA feed connector -- wraps GHSAClient behind FeedConnector protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.ghsa_client import GHSAClient


@register_connector
class GHSAConnector(FeedConnector):
    name = "ghsa"
    display_name = "GitHub Advisory Database"
    category = "package"
    source_url = "https://github.com/advisories"
    supports_cursor = True
    default_freshness_seconds = 21600

    def __init__(self) -> None:
        self._client = GHSAClient()

    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
    ) -> ConnectorResult:
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        effective_since = since
        if cursor and not effective_since:
            try:
                effective_since = datetime.fromisoformat(cursor)
            except ValueError:
                pass

        raw_advisories = await self._client.fetch_advisories(
            since=effective_since,
            limit=limit,
        )
        result.items_fetched = len(raw_advisories)

        for raw in raw_advisories:
            try:
                parsed = self._client.parse_advisory(raw)
                is_new, _ = self._client.save_advisory_to_db(session, parsed)
                if is_new:
                    result.items_new += 1
                else:
                    result.items_updated += 1
            except Exception as exc:
                ghsa_id = raw.get("ghsa_id", "unknown")
                result.errors.append({"ghsa_id": ghsa_id, "error": str(exc)})

        result.completed_at = utc_now().isoformat()
        result.cursor = utc_now().isoformat()
        return result
