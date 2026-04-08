"""Async OSV (Open Source Vulnerabilities) API client."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

from app.core.time import utc_now

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)
_MAX_RETRIES = 3


class OSVClient:
    """Async client for the OSV.dev vulnerability API."""

    def __init__(self, *, timeout: Optional[aiohttp.ClientTimeout] = None) -> None:
        self._timeout = timeout or _DEFAULT_TIMEOUT

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Issue an HTTP request with retry logic."""
        last_exc: Optional[Exception] = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                async with aiohttp.ClientSession(timeout=self._timeout) as session:
                    if method == "GET":
                        async with session.get(url) as resp:
                            resp.raise_for_status()
                            return await resp.json()
                    else:
                        async with session.post(url, json=json_body) as resp:
                            resp.raise_for_status()
                            return await resp.json()
            except (aiohttp.ClientError, TimeoutError) as exc:
                last_exc = exc
                logger.warning(
                    "OSV request %s %s attempt %d/%d failed: %s",
                    method, url, attempt, _MAX_RETRIES, exc,
                )
        raise last_exc  # type: ignore[misc]

    async def get_vuln(self, vuln_id: str) -> Dict[str, Any]:
        """GET /v1/vulns/{id} -- fetch a single vulnerability."""
        return await self._request("GET", f"{OSV_API_BASE}/vulns/{vuln_id}")

    async def query(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /v1/query -- query for vulnerabilities."""
        return await self._request("POST", f"{OSV_API_BASE}/query", json_body=body)

    async def query_batch(self, queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """POST /v1/querybatch -- batch query for vulnerabilities."""
        return await self._request(
            "POST",
            f"{OSV_API_BASE}/querybatch",
            json_body={"queries": queries},
        )

    async def fetch_recent(
        self,
        *,
        ecosystem: str = "",
        since: Optional[datetime] = None,
        limit: int = 2000,
    ) -> List[Dict[str, Any]]:
        """
        Fetch recently modified OSV advisories.

        Uses the query endpoint filtered by modified-since timestamp.
        Returns a list of full vulnerability objects (fetched individually
        because the query endpoint only returns summary stubs).
        """
        body: Dict[str, Any] = {}
        if ecosystem:
            body["package"] = {"ecosystem": ecosystem}

        if since:
            body["modified_since"] = since.isoformat()

        data = await self.query(body)
        vulns: List[Dict[str, Any]] = data.get("vulns", [])

        results: List[Dict[str, Any]] = []
        for stub in vulns[:limit]:
            vuln_id = stub.get("id")
            if not vuln_id:
                continue
            try:
                full = await self.get_vuln(vuln_id)
                results.append(full)
            except Exception as exc:
                logger.warning("Failed to fetch OSV vuln %s: %s", vuln_id, exc)
        return results

    @staticmethod
    def parse_advisory(vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalise a single OSV vulnerability object into a dict suitable
        for constructing AdvisoryRecord / PackageRecord / VersionRange rows.
        """
        vuln_id: str = vuln.get("id", "")
        summary: str = vuln.get("summary", "")
        details: str = vuln.get("details", "")
        aliases: List[str] = vuln.get("aliases", [])
        published: Optional[str] = vuln.get("published")
        modified: Optional[str] = vuln.get("modified")
        references: List[Dict[str, Any]] = vuln.get("references", [])

        cve_aliases = [a for a in aliases if a.startswith("CVE-")]

        packages: List[Dict[str, Any]] = []
        version_ranges: List[Dict[str, Any]] = []

        for affected in vuln.get("affected", []):
            pkg_info = affected.get("package", {})
            ecosystem = pkg_info.get("ecosystem", "")
            name = pkg_info.get("name", "")
            purl = pkg_info.get("purl", "")
            if ecosystem and name:
                packages.append({
                    "ecosystem": ecosystem,
                    "name": name,
                    "purl": purl,
                })

            for rng in affected.get("ranges", []):
                range_type = rng.get("type", "")
                events = rng.get("events", [])
                introduced: Optional[str] = None
                fixed: Optional[str] = None
                last_affected: Optional[str] = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                    if "last_affected" in event:
                        last_affected = event["last_affected"]

                version_ranges.append({
                    "ecosystem": ecosystem,
                    "name": name,
                    "range_type": range_type,
                    "version_start": introduced or "",
                    "version_end": last_affected or "",
                    "fixed_version": fixed or "",
                })

        return {
            "osv_id": vuln_id,
            "summary": summary,
            "details": details,
            "aliases": aliases,
            "cve_aliases": cve_aliases,
            "published": published,
            "modified": modified,
            "references": references,
            "packages": packages,
            "version_ranges": version_ranges,
            "raw": vuln,
        }
