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
from app.models.sheshnaag import AdvisoryPackageLink, AdvisoryRecord, PackageRecord, VersionRange
from app.services.advisory_normalization import (
    advisory_normalization_confidence,
    build_canonical_package,
    canonical_advisory_id,
    dedupe_references,
    parse_version_range_expression,
)

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
        version_ranges: List[Dict[str, Any]] = []
        for vuln in raw.get("vulnerabilities") or []:
            pkg = vuln.get("package") or {}
            canonical_package = build_canonical_package(pkg)
            if canonical_package["ecosystem"] and canonical_package["name"]:
                packages.append(canonical_package)
            vr = vuln.get("vulnerable_version_range")
            if vr:
                parsed_range = parse_version_range_expression(vr)
                version_ranges.append(
                    {
                        **canonical_package,
                        "range_type": "ghsa_expression",
                        "version_start": parsed_range.get("version_start") or "",
                        "version_end": parsed_range.get("version_end") or "",
                        "fixed_version": parsed_range.get("fixed_version") or "",
                        "normalized_bounds": parsed_range,
                        "raw_expression": vr,
                    }
                )

        references = dedupe_references(raw.get("references") or [])
        normalization_confidence = advisory_normalization_confidence(
            aliases=[ghsa_id, cve_id] if cve_id else [ghsa_id],
            packages=packages,
            version_ranges=version_ranges,
            references=references,
        )

        return {
            "ghsa_id": ghsa_id,
            "canonical_id": canonical_advisory_id(external_id=ghsa_id, aliases=[cve_id] if cve_id else []),
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
            "normalization_confidence": normalization_confidence,
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
            existing.canonical_id = parsed.get("canonical_id")
            existing.advisory_type = "ghsa"
            existing.severity = parsed.get("severity")
            existing.normalization_confidence = parsed.get("normalization_confidence") or 0.5
            existing.aliases = [parsed["ghsa_id"], parsed.get("cve_id")] if parsed.get("cve_id") else [parsed["ghsa_id"]]
            existing.references = parsed.get("references") or []
            existing.raw_data = {
                **parsed["raw"],
                "normalized_packages": parsed.get("packages") or [],
                "normalized_version_ranges": parsed.get("version_ranges") or [],
            }
            self._sync_package_links(session, existing, parsed)
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
            canonical_id=parsed.get("canonical_id"),
            advisory_type="ghsa",
            severity=parsed.get("severity"),
            title=parsed["summary"] or ghsa_id,
            summary=parsed["description"],
            source_url=f"https://github.com/advisories/{ghsa_id}",
            published_at=self._parse_dt(parsed.get("published_at")),
            normalization_confidence=parsed.get("normalization_confidence") or 0.5,
            aliases=[parsed["ghsa_id"], parsed.get("cve_id")] if parsed.get("cve_id") else [parsed["ghsa_id"]],
            references=parsed.get("references") or [],
            raw_data={
                **parsed["raw"],
                "normalized_packages": parsed.get("packages") or [],
                "normalized_version_ranges": parsed.get("version_ranges") or [],
            },
            cve_id=cve_fk,
        )
        session.add(advisory)
        session.flush()
        self._sync_package_links(session, advisory, parsed)

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

    def _sync_package_links(self, session: Session, advisory: AdvisoryRecord, parsed: Dict[str, Any]) -> None:
        package_rows: Dict[tuple[str, str], PackageRecord] = {}
        for pkg_info in parsed["packages"]:
            row = self._ensure_package(session, pkg_info["ecosystem"], pkg_info["name"])
            package_rows[(pkg_info["ecosystem"], pkg_info["name"])] = row
            if advisory.package_record_id is None:
                advisory.package_record_id = row.id
            existing_link = (
                session.query(AdvisoryPackageLink)
                .filter(
                    AdvisoryPackageLink.advisory_record_id == advisory.id,
                    AdvisoryPackageLink.package_record_id == row.id,
                )
                .first()
            )
            if existing_link is None:
                session.add(
                    AdvisoryPackageLink(
                        advisory_record_id=advisory.id,
                        package_record_id=row.id,
                        package_role="affected",
                        purl=pkg_info.get("purl"),
                        meta={"source": "ghsa"},
                    )
                )
                session.flush()

        for vr_info in parsed.get("version_ranges") or []:
            pkg_key = (vr_info.get("ecosystem"), vr_info.get("name"))
            pkg_row = package_rows.get(pkg_key)
            if pkg_row is None:
                continue
            existing_range = (
                session.query(VersionRange)
                .filter(
                    VersionRange.advisory_record_id == advisory.id,
                    VersionRange.package_record_id == pkg_row.id,
                    VersionRange.range_type == vr_info.get("range_type"),
                    VersionRange.version_start == (vr_info.get("version_start") or None),
                    VersionRange.version_end == (vr_info.get("version_end") or None),
                    VersionRange.fixed_version == (vr_info.get("fixed_version") or None),
                )
                .first()
            )
            if existing_range is None:
                session.add(
                    VersionRange(
                        advisory_record_id=advisory.id,
                        package_record_id=pkg_row.id,
                        cve_id=advisory.cve_id,
                        range_type=vr_info.get("range_type"),
                        source_label="ghsa",
                        version_start=vr_info.get("version_start") or None,
                        version_end=vr_info.get("version_end") or None,
                        fixed_version=vr_info.get("fixed_version") or None,
                        is_inclusive_start=bool((vr_info.get("normalized_bounds") or {}).get("inclusive_start", True)),
                        is_inclusive_end=bool((vr_info.get("normalized_bounds") or {}).get("inclusive_end", False)),
                        normalized_bounds=vr_info.get("normalized_bounds") or {},
                    )
                )

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
