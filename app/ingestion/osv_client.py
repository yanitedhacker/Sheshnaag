"""Async OSV (Open Source Vulnerabilities) API client."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import aiohttp

from app.services.advisory_normalization import (
    advisory_normalization_confidence,
    build_canonical_package,
    canonical_advisory_id,
    dedupe_references,
)

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev/v1"
_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=30)
_MAX_RETRIES = 3


class OSVClient:
    """Async client for the OSV.dev vulnerability API."""

    def __init__(self, *, timeout: aiohttp.ClientTimeout | None = None) -> None:
        self._timeout = timeout or _DEFAULT_TIMEOUT

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        """Issue an HTTP request with retry logic."""
        last_exc: Exception | None = None
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
                    method,
                    url,
                    attempt,
                    _MAX_RETRIES,
                    exc,
                )
        raise last_exc  # type: ignore[misc]

    async def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        """GET /v1/vulns/{id} -- fetch a single vulnerability."""
        return await self._request("GET", f"{OSV_API_BASE}/vulns/{vuln_id}")

    async def query(self, body: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/query -- query for vulnerabilities."""
        return await self._request("POST", f"{OSV_API_BASE}/query", json_body=body)

    async def query_batch(self, queries: list[dict[str, Any]]) -> dict[str, Any]:
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
        since: datetime | None = None,
        limit: int = 2000,
    ) -> list[dict[str, Any]]:
        """
        Fetch recently modified OSV advisories.

        Uses the query endpoint filtered by modified-since timestamp.
        Returns a list of full vulnerability objects (fetched individually
        because the query endpoint only returns summary stubs).
        """
        body: dict[str, Any] = {}
        if ecosystem:
            body["package"] = {"ecosystem": ecosystem}

        if since:
            body["modified_since"] = since.isoformat()

        data = await self.query(body)
        vulns: list[dict[str, Any]] = data.get("vulns", [])

        results: list[dict[str, Any]] = []
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
    def parse_advisory(vuln: dict[str, Any]) -> dict[str, Any]:
        """
        Normalise a single OSV vulnerability object into a dict suitable
        for constructing AdvisoryRecord / PackageRecord / VersionRange rows.
        """
        vuln_id: str = vuln.get("id", "")
        summary: str = vuln.get("summary", "")
        details: str = vuln.get("details", "")
        aliases: list[str] = vuln.get("aliases", [])
        published: str | None = vuln.get("published")
        modified: str | None = vuln.get("modified")
        references: list[dict[str, Any]] = dedupe_references(vuln.get("references", []))

        cve_aliases = [a for a in aliases if a.startswith("CVE-")]

        packages: list[dict[str, Any]] = []
        version_ranges: list[dict[str, Any]] = []

        for affected in vuln.get("affected", []):
            pkg_info = affected.get("package", {})
            ecosystem = pkg_info.get("ecosystem", "")
            name = pkg_info.get("name", "")
            canonical_package = build_canonical_package(pkg_info)
            if canonical_package["ecosystem"] and canonical_package["name"]:
                packages.append(canonical_package)

            for rng in affected.get("ranges", []):
                range_type = rng.get("type", "")
                events = rng.get("events", [])
                introduced: str | None = None
                fixed: str | None = None
                last_affected: str | None = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                    if "last_affected" in event:
                        last_affected = event["last_affected"]

                version_ranges.append(
                    {
                        "ecosystem": canonical_package["ecosystem"],
                        "name": canonical_package["name"],
                        "purl": canonical_package["purl"],
                        "range_type": range_type,
                        "version_start": introduced or "",
                        "version_end": last_affected or "",
                        "fixed_version": fixed or "",
                        "normalized_bounds": {
                            "introduced": introduced,
                            "fixed": fixed,
                            "last_affected": last_affected,
                        },
                    }
                )

        normalization_confidence = advisory_normalization_confidence(
            aliases=aliases,
            packages=packages,
            version_ranges=version_ranges,
            references=references,
        )
        return {
            "osv_id": vuln_id,
            "canonical_id": canonical_advisory_id(external_id=vuln_id, aliases=aliases),
            "summary": summary,
            "details": details,
            "aliases": aliases,
            "cve_aliases": cve_aliases,
            "published": published,
            "modified": modified,
            "references": references,
            "packages": packages,
            "version_ranges": version_ranges,
            "normalization_confidence": normalization_confidence,
            "raw": vuln,
        }
