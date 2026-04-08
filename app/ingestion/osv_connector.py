"""OSV feed connector -- wraps OSVClient behind FeedConnector protocol."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.ingestion.connector import ConnectorResult, FeedConnector, register_connector
from app.ingestion.osv_client import OSVClient
from app.models.cve import CVE
from app.models.sheshnaag import AdvisoryRecord, PackageRecord, VersionRange

logger = logging.getLogger(__name__)


def _get_or_create_package(
    session: Session,
    ecosystem: str,
    name: str,
    purl: str = "",
) -> PackageRecord:
    """Return an existing PackageRecord or create one (no commit)."""
    pkg = (
        session.query(PackageRecord)
        .filter(PackageRecord.ecosystem == ecosystem, PackageRecord.name == name)
        .first()
    )
    if pkg is not None:
        return pkg
    pkg = PackageRecord(ecosystem=ecosystem, name=name, purl=purl or None)
    session.add(pkg)
    session.flush()
    return pkg


@register_connector
class OSVConnector(FeedConnector):
    name = "osv"
    display_name = "OSV"
    category = "package"
    source_url = "https://osv.dev/"
    supports_cursor = True
    default_freshness_seconds = 21600

    def __init__(self) -> None:
        self._client = OSVClient()

    async def fetch(
        self,
        session: Session,
        *,
        since: Optional[datetime] = None,
        cursor: Optional[str] = None,
        limit: int = 2000,
    ) -> ConnectorResult:
        result = ConnectorResult(source=self.name, started_at=utc_now().isoformat())

        effective_since = since
        if cursor and not effective_since:
            try:
                effective_since = datetime.fromisoformat(cursor)
            except ValueError:
                pass

        vulns = await self._client.fetch_recent(since=effective_since, limit=limit)
        result.items_fetched = len(vulns)

        for raw_vuln in vulns:
            try:
                self._ingest_one(session, raw_vuln, result)
            except Exception as exc:
                osv_id = raw_vuln.get("id", "unknown")
                logger.warning("Error ingesting OSV %s: %s", osv_id, exc)
                result.errors.append({"osv_id": osv_id, "error": str(exc)})

        result.completed_at = utc_now().isoformat()
        result.cursor = utc_now().isoformat()
        return result

    def _ingest_one(
        self,
        session: Session,
        raw_vuln: dict,
        result: ConnectorResult,
    ) -> None:
        parsed = OSVClient.parse_advisory(raw_vuln)
        osv_id: str = parsed["osv_id"]
        payload_hash = self.hash_payload(parsed["raw"])

        existing = (
            session.query(AdvisoryRecord)
            .filter(AdvisoryRecord.external_id == osv_id)
            .first()
        )

        if existing is not None:
            existing.summary = parsed["details"] or parsed["summary"]
            existing.raw_data = parsed["raw"]
            existing.updated_at = utc_now()
            result.items_updated += 1
            advisory = existing
        else:
            cve_fk = self._resolve_cve_fk(session, parsed["cve_aliases"])

            advisory = AdvisoryRecord(
                external_id=osv_id,
                title=parsed["summary"] or osv_id,
                summary=parsed["details"] or parsed["summary"],
                source_url=f"https://osv.dev/vulnerability/{osv_id}",
                published_at=_parse_iso(parsed["published"]),
                raw_data=parsed["raw"],
                cve_id=cve_fk,
            )
            session.add(advisory)
            session.flush()
            result.items_new += 1

        for pkg_info in parsed["packages"]:
            pkg = _get_or_create_package(
                session,
                ecosystem=pkg_info["ecosystem"],
                name=pkg_info["name"],
                purl=pkg_info.get("purl", ""),
            )
            if advisory.product_id is None:
                advisory.product_id = pkg.id

        for vr_info in parsed["version_ranges"]:
            if not vr_info.get("ecosystem") or not vr_info.get("name"):
                continue
            pkg = _get_or_create_package(
                session,
                ecosystem=vr_info["ecosystem"],
                name=vr_info["name"],
            )
            vr = VersionRange(
                product_id=pkg.id,
                cve_id=advisory.cve_id,
                version_start=vr_info.get("version_start") or None,
                version_end=vr_info.get("version_end") or None,
                fixed_version=vr_info.get("fixed_version") or None,
            )
            session.add(vr)

    @staticmethod
    def _resolve_cve_fk(session: Session, cve_aliases: list[str]) -> Optional[int]:
        """Look up the internal CVE PK for the first matching alias."""
        for alias in cve_aliases:
            cve = session.query(CVE).filter(CVE.cve_id == alias).first()
            if cve is not None:
                return cve.id
        return None


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
