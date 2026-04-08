"""Data ingestion modules for threat feeds."""

from app.ingestion.connector import (
    ConnectorResult,
    FeedConnector,
    get_connector,
    get_registered_connectors,
    register_connector,
)
from app.ingestion.nvd_client import NVDClient
from app.ingestion.exploitdb_client import ExploitDBClient
from app.ingestion.feed_aggregator import FeedAggregator

# Ensure built-in connectors are registered
import app.ingestion.nvd_connector  # noqa: F401
import app.ingestion.exploitdb_connector  # noqa: F401
import app.ingestion.vendor_advisory_connector  # noqa: F401
import app.ingestion.kev_connector  # noqa: F401
import app.ingestion.epss_connector  # noqa: F401
import app.ingestion.ghsa_connector  # noqa: F401
import app.ingestion.osv_connector  # noqa: F401
import app.ingestion.patch_note_connector  # noqa: F401

__all__ = [
    "ConnectorResult",
    "FeedConnector",
    "FeedAggregator",
    "NVDClient",
    "ExploitDBClient",
    "get_connector",
    "get_registered_connectors",
    "register_connector",
]
