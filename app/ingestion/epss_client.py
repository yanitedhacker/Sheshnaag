"""Async FIRST EPSS API client."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=60)
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2


class EPSSClient:
    """Fetches and parses FIRST EPSS scores."""

    def __init__(
        self,
        url: str = EPSS_API_URL,
        timeout: aiohttp.ClientTimeout = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._max_retries = max_retries

    async def fetch_scores(
        self, *, date: Optional[str] = None, offset: int = 0, limit: int = 100
    ) -> Dict[str, Any]:
        """Fetch a page of EPSS scores with retry.

        Parameters
        ----------
        date:
            ISO date string (``YYYY-MM-DD``). ``None`` returns the latest day.
        offset / limit:
            Pagination controls accepted by the FIRST API.
        """
        import asyncio

        params: Dict[str, Any] = {"offset": offset, "limit": limit}
        if date:
            params["date"] = date

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                async with aiohttp.ClientSession() as http:
                    async with http.get(
                        self._url, params=params, timeout=self._timeout
                    ) as resp:
                        resp.raise_for_status()
                        return await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                logger.warning(
                    "EPSS fetch attempt %d/%d failed: %s",
                    attempt,
                    self._max_retries,
                    exc,
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

        raise RuntimeError(
            f"EPSS fetch failed after {self._max_retries} retries"
        ) from last_exc

    async def fetch_all_scores(self, *, date: Optional[str] = None) -> List[Dict[str, Any]]:
        """Paginate through all EPSS scores for a given date."""
        all_data: List[Dict[str, Any]] = []
        offset = 0
        page_size = 1000

        while True:
            page = await self.fetch_scores(date=date, offset=offset, limit=page_size)
            rows = page.get("data", [])
            all_data.extend(rows)

            total = int(page.get("total", 0))
            if offset + len(rows) >= total or not rows:
                break
            offset += len(rows)

        return all_data

    def parse_scores(
        self, rows: List[Dict[str, Any]], *, scored_at: datetime
    ) -> List[Dict[str, Any]]:
        """Normalise raw EPSS rows into dicts ready for persistence."""
        parsed: List[Dict[str, Any]] = []
        for row in rows:
            cve = row.get("cve", "")
            if not cve:
                continue
            parsed.append(
                {
                    "cve_id": cve.upper(),
                    "score": float(row.get("epss", 0)),
                    "percentile": float(row.get("percentile", 0)),
                    "scored_at": scored_at,
                    "raw": row,
                }
            )
        return parsed
