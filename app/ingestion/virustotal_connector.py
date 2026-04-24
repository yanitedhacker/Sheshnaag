"""VirusTotal v3 intel connector.

Normalizes VT file / url / domain / ip lookups into the shared IOC record
shape used by the V4 Threat Intel Fabric.

Environment:
    VT_API_KEY  -- VirusTotal API key (sent as ``x-apikey`` header).
"""

from __future__ import annotations

import base64
import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _vt_url_id(url: str) -> str:
    """VT v3 identifies URLs by urlsafe-b64 of the raw URL, sans ``=`` padding."""
    raw = url.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@register_ioc_connector
class VirusTotalConnector:
    """Wraps VirusTotal API v3 lookups as an IOC intel connector."""

    name: ClassVar[str] = "virustotal"
    display_name: ClassVar[str] = "VirusTotal"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://www.virustotal.com/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = VT_BASE_URL,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._api_key = api_key or os.getenv("VT_API_KEY") or ""
        self._base_url = base_url.rstrip("/")
        self._session = session or requests.Session()
        self._timeout = timeout or self.default_timeout_seconds
        self._max_retries = max_retries or self.default_max_retries
        self._backoff = backoff_seconds or self.default_backoff_seconds
        self._sleep = sleep_fn

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def healthy(self) -> bool:
        return bool(self._api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self._api_key,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # HTTP with rate-limit handling
    # ------------------------------------------------------------------

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None

        url = f"{self._base_url}{path}"
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.get(
                    url, headers=self._headers(), timeout=self._timeout
                )
            except requests.RequestException as exc:
                logger.warning(
                    "VirusTotal request error (attempt %d/%d) for %s: %s",
                    attempt, self._max_retries, path, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "VirusTotal rate limited (attempt %d/%d) for %s",
                    attempt, self._max_retries, path,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 404:
                logger.info("VirusTotal 404 for %s", path)
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "VirusTotal %s for %s (attempt %d/%d)",
                    resp.status_code, path, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "VirusTotal client error %s for %s", resp.status_code, path
                )
                return None

            try:
                return resp.json()
            except ValueError:
                logger.warning("VirusTotal response not JSON for %s", path)
                return None

        return None

    # ------------------------------------------------------------------
    # Per-kind lookups
    # ------------------------------------------------------------------

    def fetch_file(self, sha256: str) -> Optional[Dict[str, Any]]:
        if not sha256:
            return None
        body = self._get(f"/files/{sha256}")
        return self._normalize(body, indicator_kind="sha256", value=sha256) if body else None

    def fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
        if not url:
            return None
        body = self._get(f"/urls/{_vt_url_id(url)}")
        return self._normalize(body, indicator_kind="url", value=url) if body else None

    def fetch_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        if not domain:
            return None
        body = self._get(f"/domains/{domain}")
        return (
            self._normalize(body, indicator_kind="domain", value=domain)
            if body
            else None
        )

    def fetch_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        body = self._get(f"/ip_addresses/{ip}")
        return self._normalize(body, indicator_kind="ip", value=ip) if body else None

    # ------------------------------------------------------------------
    # Generic fan-out
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch a list of IOC records, one per input ``{kind, value}`` pair.

        ``scope`` shape: ``{"iocs": [{"kind": "sha256", "value": "..."}, ...]}``
        """
        if not self.healthy:
            logger.info("VirusTotal connector not healthy (no API key); returning empty")
            return []

        scope = scope or {}
        iocs = scope.get("iocs") or []
        results: List[Dict[str, Any]] = []

        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
            kind = (ioc.get("kind") or "").lower()
            value = ioc.get("value")
            if not value:
                continue
            record: Optional[Dict[str, Any]] = None
            if kind in ("sha256", "file", "hash"):
                record = self.fetch_file(value)
            elif kind == "url":
                record = self.fetch_url(value)
            elif kind == "domain":
                record = self.fetch_domain(value)
            elif kind == "ip":
                record = self.fetch_ip(value)
            else:
                logger.debug("VirusTotal skipping unsupported kind: %s", kind)
                continue
            if record is not None:
                results.append(record)

        return results

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(
        body: Dict[str, Any],
        *,
        indicator_kind: str,
        value: str,
    ) -> Dict[str, Any]:
        data = body.get("data") if isinstance(body, dict) else None
        attrs: Dict[str, Any] = {}
        if isinstance(data, dict):
            attrs = data.get("attributes") or {}

        stats = attrs.get("last_analysis_stats") or {}
        reputation = attrs.get("reputation")
        last_analysis_date = attrs.get("last_analysis_date")
        tags = attrs.get("tags") or []

        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout_cnt = int(stats.get("timeout") or 0)

        total = malicious + suspicious + harmless + undetected + timeout_cnt
        confidence = 0.0
        if total:
            confidence = round((malicious + 0.5 * suspicious) / total, 3)

        return {
            "source": "virustotal",
            "indicator_kind": indicator_kind,
            "value": value,
            "stats": {
                "harmless": harmless,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "timeout": timeout_cnt,
            },
            "last_analysis_date": last_analysis_date,
            "reputation": reputation,
            "tags": list(tags) if isinstance(tags, (list, tuple)) else [],
            "confidence": confidence,
            "raw": data,
        }
