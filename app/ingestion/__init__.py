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

# Ensure built-in CVE/advisory connectors are registered
import app.ingestion.nvd_connector  # noqa: F401
import app.ingestion.exploitdb_connector  # noqa: F401
import app.ingestion.vendor_advisory_connector  # noqa: F401
import app.ingestion.kev_connector  # noqa: F401
import app.ingestion.epss_connector  # noqa: F401
import app.ingestion.ghsa_connector  # noqa: F401
import app.ingestion.osv_connector  # noqa: F401
import app.ingestion.patch_note_connector  # noqa: F401

# V4 Pillar 3 -- IOC intel connectors (separate registry, scope-dict fetch)
from app.ingestion.misp_connector import (  # noqa: F401
    MISPConnector,
    get_ioc_connector,
    get_registered_ioc_connectors,
    register_ioc_connector,
)
import app.ingestion.virustotal_connector  # noqa: F401
import app.ingestion.otx_connector  # noqa: F401
import app.ingestion.abusech_connector  # noqa: F401
import app.ingestion.opencti_connector  # noqa: F401
import app.ingestion.mandiant_connector  # noqa: F401
import app.ingestion.shodan_connector  # noqa: F401

__all__ = [
    "ConnectorResult",
    "FeedConnector",
    "FeedAggregator",
    "NVDClient",
    "ExploitDBClient",
    "get_connector",
    "get_registered_connectors",
    "register_connector",
    "MISPConnector",
    "get_ioc_connector",
    "get_registered_ioc_connectors",
    "register_ioc_connector",
]
