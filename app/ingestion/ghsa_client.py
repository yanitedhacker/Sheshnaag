"""GitHub Advisory Database (GHSA) API client."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.ingestion.connector import FeedConnector
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryRecord, PackageRecord

logger = logging.getLogger(__name__)


class GHSAClient:
    """Async client for the GitHub Advisory Database REST API."""

    BASE_URL = "https://api.github.com/advisories"
    MAX_RETRIES = 3
    TIMEOUT = aiohttp.ClientTimeout(total=30)

    def __init__(self, token: Optional[str] = None) -> None:
        self._token = token or settings.github_token
        self._headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            self._headers["Authorization"] = f"Bearer {self._token}"

    async def fetch_advisories(
        self,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        per_page: int = 100,
        limit: int = 2000,
    ) -> List[Dict[str, Any]]:
        """Fetch reviewed advisories, paginating until *limit* is reached."""
        all_advisories: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {
            "type": "reviewed",
            "per_page": min(per_page, 100),
        }
        if since:
            params["updated"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        if cursor:
            params["after"] = cursor

        async with aiohttp.ClientSession(headers=self._headers) as http:
            page_url: Optional[str] = self.BASE_URL
            while page_url and len(all_advisories) < limit:
                data = await self._get_with_retry(http, page_url, params)
                if data is None:
                    break
                all_advisories.extend(data)
                page_url = None
                params = {}

                if len(data) == per_page and len(all_advisories) < limit:
                    last = data[-1]
                    page_url = self.BASE_URL
                    params = {
                        "type": "reviewed",
                        "per_page": min(per_page, 100),
                        "after": last.get("ghsa_id", ""),
                    }
                    if since:
                        params["updated"] = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        logger.info("Fetched %d GHSA advisories", len(all_advisories))
        return all_advisories[:limit]

    async def _get_with_retry(
        self,
        http: aiohttp.ClientSession,
        url: str,
        params: Dict[str, Any],
    ) -> Optional[List[Dict[str, Any]]]:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                async with http.get(url, params=params, timeout=self.TIMEOUT) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning(
                        "GHSA API returned %d (attempt %d/%d)",
                        resp.status, attempt, self.MAX_RETRIES,
                    )
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "GHSA request error (attempt %d/%d): %s",
                    attempt, self.MAX_RETRIES, exc,
                )
        if last_exc:
            logger.error("GHSA fetch failed after %d retries: %s", self.MAX_RETRIES, last_exc)
        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_ghsa_id(raw_id: str) -> str:
        """Ensure consistent ``GHSA-xxxx-xxxx-xxxx`` formatting."""
        return raw_id.strip().upper()

    def parse_advisory(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single GHSA advisory JSON into a normalized dict."""
        ghsa_id = self.normalize_ghsa_id(raw.get("ghsa_id", ""))
        cve_id = raw.get("cve_id") or None
        severity = (raw.get("severity") or "").lower()

        packages: List[Dict[str, str]] = []
        version_ranges: List[str] = []
        for vuln in raw.get("vulnerabilities") or []:
            pkg = vuln.get("package") or {}
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if ecosystem and name:
                packages.append({"ecosystem": ecosystem, "name": name})
            vr = vuln.get("vulnerable_version_range")
            if vr:
                version_ranges.append(vr)

        references: List[str] = [
            ref.get("url", "") for ref in (raw.get("references") or []) if ref.get("url")
        ]

        return {
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "summary": raw.get("summary", ""),
            "description": raw.get("description", ""),
            "severity": severity,
            "packages": packages,
            "version_ranges": version_ranges,
            "references": references,
            "published_at": raw.get("published_at"),
            "updated_at": raw.get("updated_at"),
            "raw": raw,
            "payload_hash": FeedConnector.hash_payload(raw),
        }

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save_advisory_to_db(
        self,
        session: Session,
        parsed: Dict[str, Any],
    ) -> tuple[bool, AdvisoryRecord]:
        """
        Persist a parsed advisory into the database.

        Returns ``(is_new, advisory_record)``.
        """
        ghsa_id = parsed["ghsa_id"]

        existing = (
            session.query(AdvisoryRecord)
            .filter(AdvisoryRecord.external_id == ghsa_id)
            .first()
        )
        if existing:
            existing.title = parsed["summary"] or existing.title
            existing.summary = parsed["description"]
            existing.raw_data = parsed["raw"]
            return False, existing

        cve_fk: Optional[int] = None
        if parsed["cve_id"]:
            cve_row = (
                session.query(CVE)
                .filter(CVE.cve_id == parsed["cve_id"])
                .first()
            )
            if cve_row:
                cve_fk = cve_row.id

        advisory = AdvisoryRecord(
            external_id=ghsa_id,
            title=parsed["summary"] or ghsa_id,
            summary=parsed["description"],
            source_url=f"https://github.com/advisories/{ghsa_id}",
            published_at=self._parse_dt(parsed.get("published_at")),
            raw_data=parsed["raw"],
            cve_id=cve_fk,
        )
        session.add(advisory)
        session.flush()

        for pkg_info in parsed["packages"]:
            self._ensure_package(session, pkg_info["ecosystem"], pkg_info["name"])

        return True, advisory

    @staticmethod
    def _ensure_package(session: Session, ecosystem: str, name: str) -> PackageRecord:
        """Get-or-create a PackageRecord row."""
        existing = (
            session.query(PackageRecord)
            .filter(
                PackageRecord.ecosystem == ecosystem,
                PackageRecord.name == name,
            )
            .first()
        )
        if existing:
            return existing
        pkg = PackageRecord(ecosystem=ecosystem, name=name)
        session.add(pkg)
        session.flush()
        return pkg

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
