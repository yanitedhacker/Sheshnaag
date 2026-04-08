"""Feed connector protocol and registry for pluggable source ingestion."""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional, Type

from sqlalchemy.orm import Session

from app.core.time import utc_now

logger = logging.getLogger(__name__)


@dataclass
class ConnectorResult:
    """Normalized result from a single connector sync."""

    source: str
    items_fetched: int = 0
    items_new: int = 0
    items_updated: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    cursor: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "items_fetched": self.items_fetched,
            "items_new": self.items_new,
            "items_updated": self.items_updated,
            "errors": self.errors,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class FeedConnector(ABC):
    """
    Protocol for pluggable feed sources.

    Every new intel source (OSV, GHSA, KEV, EPSS, vendor advisories, etc.)
    implements this interface.  The aggregator discovers and iterates all
    registered connectors instead of hard-coding source-specific branches.
    """

    name: ClassVar[str]
    display_name: ClassVar[str]
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = ""
    supports_cursor: ClassVar[bool] = False
    default_freshness_seconds: ClassVar[int] = 21600  # 6 hours

    @abstractmethod
    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
    ) -> ConnectorResult:
        """
        Run one sync cycle.

        Implementations should:
        - Fetch raw data from the upstream source
        - Normalize into project models (AdvisoryRecord / PackageRecord / CVE etc.)
        - Persist via the provided *session* (do NOT commit -- caller manages tx)
        - Return a ConnectorResult summarising the run
        """

    def freshness_seconds(self) -> int:
        return self.default_freshness_seconds

    # Utility helpers shared by all connectors --------------------------------

    @staticmethod
    def hash_payload(payload: Any) -> str:
        """SHA-256 digest of the JSON-serialised payload."""
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Global connector registry
# ---------------------------------------------------------------------------

_CONNECTOR_REGISTRY: Dict[str, Type[FeedConnector]] = {}


def register_connector(cls: Type[FeedConnector]) -> Type[FeedConnector]:
    """Class decorator that registers a FeedConnector subclass."""
    if not hasattr(cls, "name") or not cls.name:
        raise ValueError(f"Connector {cls.__name__} must define a 'name' class attribute")
    _CONNECTOR_REGISTRY[cls.name] = cls
    logger.debug("Registered feed connector: %s", cls.name)
    return cls


def get_registered_connectors() -> Dict[str, Type[FeedConnector]]:
    """Return a snapshot of all registered connectors."""
    return dict(_CONNECTOR_REGISTRY)


def get_connector(name: str) -> Optional[Type[FeedConnector]]:
    return _CONNECTOR_REGISTRY.get(name)
