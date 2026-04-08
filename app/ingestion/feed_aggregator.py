"""Feed aggregator for coordinating multiple threat intelligence sources."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import FeedConnector, ConnectorResult, get_registered_connectors
from app.ingestion.sync_state import get_or_create_state, mark_failed, mark_running, mark_success, record_sync_run
from app.models.sheshnaag import SourceFeed

logger = logging.getLogger(__name__)

# Ensure built-in connectors are registered on import
import app.ingestion.nvd_connector as _nvd_reg  # noqa: F401
import app.ingestion.exploitdb_connector as _edb_reg  # noqa: F401


class FeedAggregator:
    """Coordinates ingestion from all registered feed connectors."""

    def __init__(self, session: Session, *, connectors: Optional[List[FeedConnector]] = None):
        self.session = session
        if connectors is not None:
            self._connectors = {c.name: c for c in connectors}
        else:
            self._connectors = {
                name: cls() for name, cls in get_registered_connectors().items()
            }

    @property
    def connector_names(self) -> List[str]:
        return list(self._connectors.keys())

    def get_connector(self, name: str) -> Optional[FeedConnector]:
        return self._connectors.get(name)

    async def sync_connector(
        self,
        name: str,
        *,
        days: int = 7,
        limit: int = 2000,
    ) -> ConnectorResult:
        """Run a single named connector with state tracking."""
        connector = self._connectors.get(name)
        if connector is None:
            raise ValueError(f"Unknown connector: {name}")

        state_key = name.upper()
        state = get_or_create_state(self.session, state_key)
        mark_running(self.session, state)
        self.session.commit()

        try:
            since: Optional[datetime] = None
            cursor: Optional[str] = state.cursor if connector.supports_cursor else None
            if cursor:
                try:
                    since = datetime.fromisoformat(cursor)
                except ValueError:
                    since = None

            result = await connector.fetch(
                self.session,
                since=since,
                cursor=cursor,
                limit=limit,
            )
            self.session.commit()

            mark_success(self.session, state, cursor=result.cursor)

            payload_hash = getattr(connector, '_last_payload_hash', None)
            record_sync_run(
                self.session,
                result,
                status="success",
                raw_payload_hash=payload_hash,
            )

            feed = self.session.query(SourceFeed).filter(
                SourceFeed.feed_key == name,
            ).first()
            if feed:
                feed.last_synced_at = utc_now()
                feed.status = "active"
                if payload_hash:
                    feed.raw_payload_hash = payload_hash
                self.session.add(feed)

            self.session.commit()
            return result

        except Exception as exc:
            self.session.rollback()
            mark_failed(self.session, state, str(exc))
            failed_result = ConnectorResult(source=name, started_at=utc_now().isoformat())
            record_sync_run(
                self.session,
                failed_result,
                status="failed",
                error_summary=str(exc)[:500],
            )
            self.session.commit()
            raise

    async def sync_with_state(self, days: int = 7, exploit_limit: int = 2000) -> Dict[str, Any]:
        """
        Full sync using persisted cursor state for incremental updates.

        Iterates all registered connectors in registration order.
        """
        results: Dict[str, Any] = {
            "started_at": utc_now().isoformat(),
            "completed_at": None,
            "connectors": {},
        }

        for name in self._connectors:
            try:
                cr = await self.sync_connector(name, days=days, limit=exploit_limit)
                results["connectors"][name] = cr.to_dict()
            except Exception as exc:
                logger.error("Connector %s failed: %s", name, exc)
                results["connectors"][name] = {"error": str(exc)}

        results["completed_at"] = utc_now().isoformat()
        return results

    async def full_sync(self, days: int = 30) -> Dict[str, Any]:
        """Perform a full synchronization of all feeds."""
        logger.info("Starting full sync for last %d days", days)
        return await self.sync_with_state(days=days)

    # Legacy compatibility helpers -------------------------------------------

    async def sync_recent_cves(self, days: int = 7, since: Optional[datetime] = None) -> Dict[str, Any]:
        """Backwards-compatible CVE sync via the NVD connector."""
        connector = self._connectors.get("nvd")
        if connector is None:
            return {"error": "NVD connector not registered"}
        result = await connector.fetch(self.session, since=since, limit=2000)
        self.session.commit()
        return result.to_dict()

    async def sync_recent_exploits_from_mirror(self, since: Optional[datetime] = None, limit: int = 2000) -> Dict[str, Any]:
        """Backwards-compatible exploit sync via the ExploitDB connector."""
        connector = self._connectors.get("exploit_db")
        if connector is None:
            return {"error": "ExploitDB connector not registered"}
        result = await connector.fetch(self.session, since=since, limit=limit)
        self.session.commit()
        return result.to_dict()
