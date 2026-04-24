"""AlienVault OTX intel connector.

Normalizes OTX pulses and indicator lookups into the shared IOC record
shape used by the V4 Threat Intel Fabric.

Environment:
    OTX_API_KEY  -- OTX API key (sent as ``X-OTX-API-KEY`` header).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# OTX indicator "type" → normalized indicator_kind
_OTX_TYPE_MAP: Dict[str, str] = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "FileHash-PEHASH": "pehash",
    "FileHash-IMPHASH": "imphash",
    "email": "email",
    "Mutex": "mutex",
    "CVE": "cve",
    "YARA": "yara",
}


def _map_indicator_kind(otx_type: str) -> str:
    return _OTX_TYPE_MAP.get(otx_type, (otx_type or "unknown").lower())


@register_ioc_connector
class OTXConnector:
    """Pulls pulses and indicator lookups from AlienVault OTX."""

    name: ClassVar[str] = "otx"
    display_name: ClassVar[str] = "AlienVault OTX"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://otx.alienvault.com/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = OTX_BASE_URL,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._api_key = api_key or os.getenv("OTX_API_KEY") or ""
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
            "X-OTX-API-KEY": self._api_key,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None
        url = f"{self._base_url}{path}"
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.get(
                    url,
                    headers=self._headers(),
                    params=params,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "OTX request error (attempt %d/%d) for %s: %s",
                    attempt, self._max_retries, path, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "OTX rate limited (attempt %d/%d) for %s",
                    attempt, self._max_retries, path,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 404:
                logger.info("OTX 404 for %s", path)
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "OTX %s for %s (attempt %d/%d)",
                    resp.status_code, path, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "OTX client error %s for %s", resp.status_code, path
                )
                return None

            try:
                return resp.json()
            except ValueError:
                logger.warning("OTX response not JSON for %s", path)
                return None

        return None

    # ------------------------------------------------------------------
    # Public lookups
    # ------------------------------------------------------------------

    def fetch_pulses_subscribed(
        self,
        *,
        limit: int = 50,
        page: int = 1,
        modified_since: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if modified_since:
            params["modified_since"] = modified_since
        body = self._get("/pulses/subscribed", params=params)
        if not body:
            return []
        return self._normalize_pulses(body.get("results") or [])

    def fetch_indicator(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        kind_path = self._kind_to_otx_path(kind)
        if not kind_path or not value:
            return None
        body = self._get(f"/indicators/{kind_path}/{value}/general")
        if not body:
            return None
        return self._normalize_indicator(body, indicator_kind=kind, value=value)

    # ------------------------------------------------------------------
    # Generic fetch
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch either pulses or per-indicator lookups.

        ``scope`` shape:
            - ``{"mode": "pulses", "limit": 50, "page": 1}`` (default)
            - ``{"mode": "indicators", "iocs": [{"kind", "value"}, ...]}``
        """
        if not self.healthy:
            logger.info("OTX connector not healthy (no API key); returning empty")
            return []

        scope = scope or {}
        mode = (scope.get("mode") or "pulses").lower()

        if mode == "indicators":
            results: List[Dict[str, Any]] = []
            for ioc in scope.get("iocs") or []:
                if not isinstance(ioc, dict):
                    continue
                kind = (ioc.get("kind") or "").lower()
                value = ioc.get("value")
                if not value:
                    continue
                record = self.fetch_indicator(kind, value)
                if record is not None:
                    results.append(record)
            return results

        return self.fetch_pulses_subscribed(
            limit=int(scope.get("limit", 50)),
            page=int(scope.get("page", 1)),
            modified_since=scope.get("modified_since"),
        )

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def _normalize_pulses(
        self, pulses: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for pulse in pulses:
            if not isinstance(pulse, dict):
                continue
            pulse_id = str(pulse.get("id") or "")
            pulse_name = pulse.get("name") or ""
            tags = list(pulse.get("tags") or [])
            first_seen = pulse.get("created")
            last_seen = pulse.get("modified") or pulse.get("created")
            for indicator in pulse.get("indicators") or []:
                if not isinstance(indicator, dict):
                    continue
                value = indicator.get("indicator")
                if not value:
                    continue
                kind = _map_indicator_kind(indicator.get("type", ""))
                records.append(
                    {
                        "source": "otx",
                        "event_id": pulse_id,
                        "event_info": pulse_name,
                        "indicator_kind": kind,
                        "value": str(value),
                        "tags": tags,
                        "confidence": 0.6,
                        "first_seen": indicator.get("created") or first_seen,
                        "last_seen": last_seen,
                        "raw": indicator,
                    }
                )
        return records

    @staticmethod
    def _normalize_indicator(
        body: Dict[str, Any],
        *,
        indicator_kind: str,
        value: str,
    ) -> Dict[str, Any]:
        pulse_info = body.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        tags: List[str] = []
        for pulse in pulses:
            if isinstance(pulse, dict):
                tags.extend(pulse.get("tags") or [])
        pulse_count = int(pulse_info.get("count") or len(pulses))
        # A crude confidence score: more pulses referencing it => higher.
        if pulse_count == 0:
            confidence = 0.1
        elif pulse_count < 3:
            confidence = 0.4
        elif pulse_count < 10:
            confidence = 0.65
        else:
            confidence = 0.85
        return {
            "source": "otx",
            "indicator_kind": indicator_kind,
            "value": value,
            "pulse_count": pulse_count,
            "tags": sorted(set(tags)),
            "confidence": confidence,
            "first_seen": body.get("first_seen") or body.get("whois"),
            "last_seen": body.get("last_seen") or body.get("modified"),
            "raw": body,
        }

    @staticmethod
    def _kind_to_otx_path(kind: str) -> Optional[str]:
        mapping = {
            "ip": "IPv4",
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "hostname": "hostname",
            "url": "url",
            "md5": "file",
            "sha1": "file",
            "sha256": "file",
            "file": "file",
            "cve": "cve",
        }
        return mapping.get((kind or "").lower())
