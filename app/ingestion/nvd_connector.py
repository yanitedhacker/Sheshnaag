"""NVD feed connector -- wraps NVDClient behind FeedConnector protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.nvd_client import NVDClient
from app.models.cve import CVE


@register_connector
class NVDConnector(FeedConnector):
    name = "nvd"
    display_name = "NVD"
    category = "intel"
    source_url = "https://nvd.nist.gov/"
    supports_cursor = True
    default_freshness_seconds = 21600

    def __init__(self) -> None:
        self._client = NVDClient()

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

        raw_cves = await self._client.fetch_recent_cves(days=7, since=effective_since)
        result.items_fetched = len(raw_cves)

        for raw_cve in raw_cves:
            try:
                parsed = self._client.parse_cve(raw_cve)
                existing = session.query(CVE).filter(CVE.cve_id == parsed["cve_id"]).first()
                self._client.save_cve_to_db(session, parsed)
                if existing:
                    result.items_updated += 1
                else:
                    result.items_new += 1
            except Exception as exc:
                cve_id = raw_cve.get("cve", {}).get("id", "unknown")
                result.errors.append({"cve_id": cve_id, "error": str(exc)})

        result.completed_at = utc_now().isoformat()
        result.cursor = utc_now().isoformat()
        return result
