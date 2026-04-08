"""Vendor advisory adapter framework for pluggable vendor-specific parsers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


NormalizedAdvisory = Dict[str, Any]
"""
Expected shape:
{
    "vendor": str,
    "advisory_id": str,
    "title": str,
    "summary": str,
    "source_url": str,
    "published_at": Optional[datetime],
    "severity": Optional[str],
    "affected_products": [{"name": str, "version_hint": str}],
    "cve_ids": [str],
    "raw_data": dict,
}
"""

REQUIRED_FIELDS = {"vendor", "advisory_id", "title", "summary", "source_url"}


def validate_normalized(payload: NormalizedAdvisory) -> None:
    """Raise ``ValueError`` if *payload* is missing required keys."""
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise ValueError(f"Normalized advisory missing required fields: {missing}")


# ---------------------------------------------------------------------------
# Abstract parser base
# ---------------------------------------------------------------------------


class VendorAdvisoryParser(ABC):
    """Base class for vendor-specific advisory parsers.

    Sub-classes implement ``vendor_name`` and ``parse`` -- everything else
    is handled by the connector and registry.
    """

    @abstractmethod
    def vendor_name(self) -> str:
        """Return the canonical lowercase vendor identifier."""

    @abstractmethod
    def parse(self, raw_data: dict) -> List[NormalizedAdvisory]:
        """Normalise raw upstream data into a list of advisory dicts."""


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------


class VendorAdvisoryRegistry:
    """Manual registry mapping vendor names to parser instances."""

    def __init__(self) -> None:
        self._parsers: Dict[str, VendorAdvisoryParser] = {}

    def register(self, parser: VendorAdvisoryParser) -> None:
        name = parser.vendor_name()
        self._parsers[name] = parser
        logger.debug("Registered vendor advisory parser: %s", name)

    def get(self, vendor: str) -> Optional[VendorAdvisoryParser]:
        return self._parsers.get(vendor)

    def all_parsers(self) -> Dict[str, VendorAdvisoryParser]:
        return dict(self._parsers)


# ---------------------------------------------------------------------------
# Default global registry instance
# ---------------------------------------------------------------------------

default_registry = VendorAdvisoryRegistry()


# ---------------------------------------------------------------------------
# Example parser for testing / reference
# ---------------------------------------------------------------------------

EXAMPLE_FIXTURE: Dict[str, Any] = {
    "id": "EX-2025-001",
    "title": "Example Widget RCE",
    "description": "A remote code execution in Example Widget <=2.3.0",
    "url": "https://example.com/security/EX-2025-001",
    "date": "2025-06-15T00:00:00+00:00",
    "severity": "critical",
    "products": [
        {"name": "Example Widget", "version": "<=2.3.0"},
    ],
    "cves": ["CVE-2025-99999"],
}


class ExampleVendorParser(VendorAdvisoryParser):
    """Reference parser that transforms static fixture data."""

    def vendor_name(self) -> str:
        return "example_vendor"

    def parse(self, raw_data: dict) -> List[NormalizedAdvisory]:
        published_at: Optional[datetime] = None
        if raw_data.get("date"):
            try:
                published_at = datetime.fromisoformat(raw_data["date"])
            except (ValueError, TypeError):
                pass

        affected = [
            {"name": p["name"], "version_hint": p.get("version", "")}
            for p in raw_data.get("products", [])
        ]

        advisory: NormalizedAdvisory = {
            "vendor": self.vendor_name(),
            "advisory_id": raw_data.get("id", ""),
            "title": raw_data.get("title", ""),
            "summary": raw_data.get("description", ""),
            "source_url": raw_data.get("url", ""),
            "published_at": published_at,
            "severity": raw_data.get("severity"),
            "affected_products": affected,
            "cve_ids": raw_data.get("cves", []),
            "raw_data": raw_data,
        }
        return [advisory]
