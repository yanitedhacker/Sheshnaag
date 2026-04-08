"""Patch note adapter framework for pluggable vendor-specific release/changelog parsers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


NormalizedPatchNote = Dict[str, Any]
"""
Expected shape:
{
    "source": str,
    "note_id": str,
    "title": str,
    "summary": str,
    "source_url": str,
    "published_at": Optional[datetime],
    "product_name": Optional[str],
    "product_version": Optional[str],
    "cve_ids": [str],
    "package_hints": [{"ecosystem": str, "name": str}],
    "raw_data": dict,
}
"""

REQUIRED_FIELDS = {"source", "note_id", "title", "summary", "source_url"}


def validate_patch_note(payload: NormalizedPatchNote) -> None:
    """Raise ``ValueError`` if *payload* is missing required keys."""
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise ValueError(f"Normalized patch note missing required fields: {missing}")


# ---------------------------------------------------------------------------
# Abstract parser base
# ---------------------------------------------------------------------------


class PatchNoteParser(ABC):
    """Base class for vendor-specific patch note / changelog parsers.

    Sub-classes implement ``source_name`` and ``parse`` -- everything else
    is handled by the connector and registry.
    """

    @abstractmethod
    def source_name(self) -> str:
        """Return the canonical lowercase source identifier."""

    @abstractmethod
    def parse(self, raw_data: dict) -> List[NormalizedPatchNote]:
        """Normalise raw upstream data into a list of patch note dicts."""


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------


class PatchNoteRegistry:
    """Manual registry mapping source names to parser instances."""

    def __init__(self) -> None:
        self._parsers: Dict[str, PatchNoteParser] = {}

    def register(self, parser: PatchNoteParser) -> None:
        name = parser.source_name()
        self._parsers[name] = parser
        logger.debug("Registered patch note parser: %s", name)

    def get(self, source: str) -> Optional[PatchNoteParser]:
        return self._parsers.get(source)

    def all_parsers(self) -> Dict[str, PatchNoteParser]:
        return dict(self._parsers)


# ---------------------------------------------------------------------------
# Default global registry instance
# ---------------------------------------------------------------------------

default_registry = PatchNoteRegistry()


# ---------------------------------------------------------------------------
# Example parser for testing / reference
# ---------------------------------------------------------------------------

EXAMPLE_PATCH_NOTE_FIXTURE: Dict[str, Any] = {
    "id": "PN-2025-042",
    "title": "Acme Firewall v3.2.1 Security Patch",
    "description": "Fixes critical RCE and two privilege-escalation issues in Acme Firewall.",
    "url": "https://acme.example.com/releases/3.2.1",
    "date": "2025-07-01T00:00:00+00:00",
    "product": "Acme Firewall",
    "version": "3.2.1",
    "fixed_cves": ["CVE-2025-11111", "CVE-2025-22222"],
    "packages": [
        {"ecosystem": "deb", "name": "acme-firewall"},
    ],
}


class ExamplePatchNoteParser(PatchNoteParser):
    """Reference parser that transforms static fixture data."""

    def source_name(self) -> str:
        return "example_patch_source"

    def parse(self, raw_data: dict) -> List[NormalizedPatchNote]:
        published_at: Optional[datetime] = None
        if raw_data.get("date"):
            try:
                published_at = datetime.fromisoformat(raw_data["date"])
            except (ValueError, TypeError):
                pass

        package_hints = [
            {"ecosystem": p["ecosystem"], "name": p["name"]}
            for p in raw_data.get("packages", [])
        ]

        note: NormalizedPatchNote = {
            "source": self.source_name(),
            "note_id": raw_data.get("id", ""),
            "title": raw_data.get("title", ""),
            "summary": raw_data.get("description", ""),
            "source_url": raw_data.get("url", ""),
            "published_at": published_at,
            "product_name": raw_data.get("product"),
            "product_version": raw_data.get("version"),
            "cve_ids": raw_data.get("fixed_cves", []),
            "package_hints": package_hints,
            "raw_data": raw_data,
        }
        return [note]
