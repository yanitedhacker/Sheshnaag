"""Async CISA KEV catalog client."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=60)
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2


class KEVClient:
    """Fetches and parses the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(
        self,
        url: str = KEV_CATALOG_URL,
        timeout: aiohttp.ClientTimeout = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._max_retries = max_retries

    async def fetch_catalog(self) -> Dict[str, Any]:
        """Download the full KEV catalog JSON with retry."""
        import asyncio

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with aiohttp.ClientSession() as http:
                    async with http.get(self._url, timeout=self._timeout) as resp:
                        resp.raise_for_status()
                        return await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                logger.warning(
                    "KEV fetch attempt %d/%d failed: %s",
                    attempt,
                    self._max_retries,
                    exc,
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

        raise RuntimeError(f"KEV fetch failed after {self._max_retries} retries") from last_exc

    def parse_vulnerabilities(self, catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalise individual vulnerability entries."""
        raw_vulns = catalog.get("vulnerabilities", [])
        parsed: List[Dict[str, Any]] = []

        for v in raw_vulns:
            parsed.append(
                {
                    "cve_id": v.get("cveID", ""),
                    "vendor_project": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability_name": v.get("vulnerabilityName"),
                    "date_added": self._parse_date(v.get("dateAdded")),
                    "short_description": v.get("shortDescription"),
                    "required_action": v.get("requiredAction"),
                    "due_date": self._parse_date(v.get("dueDate")),
                    "known_ransomware_campaign_use": v.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    ),
                    "raw": v,
                }
            )

        return parsed

    @staticmethod
    def _parse_date(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            try:
                return datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                return None
