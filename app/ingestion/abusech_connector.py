"""abuse.ch intel connector bundling URLhaus + MalwareBazaar + ThreatFox.

All three abuse.ch APIs share a single authentication header ``Auth-Key``
(see https://abuse.ch/api/ for the unified auth rollout).  This connector
normalizes their responses into the shared IOC record shape used by the
V4 Threat Intel Fabric.

Environment:
    ABUSECH_AUTH_KEY  -- abuse.ch auth key (sent as ``Auth-Key`` header).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _threatfox_kind(ioc_type: str) -> str:
    mapping = {
        "ip:port": "ip",
        "ip": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "md5",
        "sha1_hash": "sha1",
        "sha256_hash": "sha256",
        "sha3_384_hash": "sha3_384",
    }
    return mapping.get(ioc_type, ioc_type or "unknown")


@register_ioc_connector
class AbuseChConnector:
    """Aggregates URLhaus + MalwareBazaar + ThreatFox under one IOC connector."""

    name: ClassVar[str] = "abusech"
    display_name: ClassVar[str] = "abuse.ch"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://abuse.ch/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        auth_key: Optional[str] = None,
        *,
        urlhaus_url: str = URLHAUS_URL,
        malwarebazaar_url: str = MALWAREBAZAAR_URL,
        threatfox_url: str = THREATFOX_URL,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._auth_key = auth_key or os.getenv("ABUSECH_AUTH_KEY") or ""
        self._urlhaus_url = urlhaus_url
        self._mb_url = malwarebazaar_url
        self._threatfox_url = threatfox_url
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
        return bool(self._auth_key)

    def _headers(self) -> Dict[str, str]:
        return {"Auth-Key": self._auth_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # HTTP with retry
    # ------------------------------------------------------------------

    def _post(
        self,
        url: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.post(
                    url,
                    headers=self._headers(),
                    data=data,
                    json=json_body,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "abuse.ch request error (attempt %d/%d) for %s: %s",
                    attempt, self._max_retries, url, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "abuse.ch rate limited (attempt %d/%d) for %s",
                    attempt, self._max_retries, url,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 500:
                logger.warning(
                    "abuse.ch %s for %s (attempt %d/%d)",
                    resp.status_code, url, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "abuse.ch client error %s for %s",
                    resp.status_code, url,
                )
                return None

            try:
                return resp.json()
            except ValueError:
                logger.warning("abuse.ch response not JSON for %s", url)
                return None

        return None

    # ------------------------------------------------------------------
    # URLhaus
    # ------------------------------------------------------------------

    def fetch_urlhaus(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.healthy:
            logger.info("abuse.ch not healthy; skipping URLhaus")
            return []

        body = self._post(self._urlhaus_url, data={"limit": str(int(limit))})
        if not body:
            return []

        if body.get("query_status") not in ("ok", None):
            logger.info("URLhaus query_status=%s", body.get("query_status"))
            return []

        urls = body.get("urls") or body.get("payload") or []
        records: List[Dict[str, Any]] = []
        for entry in urls:
            if not isinstance(entry, dict):
                continue
            url_value = entry.get("url")
            if not url_value:
                continue
            tags = list(entry.get("tags") or [])
            threat = entry.get("threat")
            if threat and threat not in tags:
                tags.append(threat)
            records.append(
                {
                    "source": "urlhaus",
                    "event_id": str(entry.get("id") or entry.get("url_id") or ""),
                    "event_info": entry.get("threat") or "urlhaus",
                    "indicator_kind": "url",
                    "value": url_value,
                    "tags": tags,
                    "confidence": 0.85
                    if entry.get("url_status") == "online"
                    else 0.5,
                    "first_seen": entry.get("date_added"),
                    "last_seen": entry.get("last_online") or entry.get("date_added"),
                    "raw": entry,
                }
            )
        return records

    # ------------------------------------------------------------------
    # MalwareBazaar
    # ------------------------------------------------------------------

    def fetch_malwarebazaar(self, limit: int = 100) -> List[Dict[str, Any]]:
        if not self.healthy:
            logger.info("abuse.ch not healthy; skipping MalwareBazaar")
            return []

        body = self._post(
            self._mb_url,
            data={"query": "get_recent", "selector": "time"},
        )
        if not body:
            return []

        if body.get("query_status") not in ("ok", None):
            logger.info("MalwareBazaar query_status=%s", body.get("query_status"))
            return []

        samples = body.get("data") or []
        records: List[Dict[str, Any]] = []
        for sample in samples[: max(0, int(limit))]:
            if not isinstance(sample, dict):
                continue
            sha256 = sample.get("sha256_hash")
            if not sha256:
                continue
            tags = list(sample.get("tags") or [])
            signature = sample.get("signature")
            if signature and signature not in tags:
                tags.append(signature)
            records.append(
                {
                    "source": "malwarebazaar",
                    "event_id": sha256,
                    "event_info": sample.get("file_name")
                    or signature
                    or "malwarebazaar",
                    "indicator_kind": "sha256",
                    "value": sha256,
                    "tags": tags,
                    "confidence": 0.9,
                    "first_seen": sample.get("first_seen"),
                    "last_seen": sample.get("last_seen") or sample.get("first_seen"),
                    "raw": sample,
                }
            )
        return records

    # ------------------------------------------------------------------
    # ThreatFox
    # ------------------------------------------------------------------

    def fetch_threatfox(self, days: int = 1) -> List[Dict[str, Any]]:
        if not self.healthy:
            logger.info("abuse.ch not healthy; skipping ThreatFox")
            return []

        body = self._post(
            self._threatfox_url,
            json_body={"query": "get_iocs", "days": int(days)},
        )
        if not body:
            return []

        if body.get("query_status") not in ("ok", None):
            logger.info("ThreatFox query_status=%s", body.get("query_status"))
            return []

        iocs = body.get("data") or []
        records: List[Dict[str, Any]] = []
        for entry in iocs:
            if not isinstance(entry, dict):
                continue
            value = entry.get("ioc")
            if not value:
                continue
            kind = _threatfox_kind(entry.get("ioc_type", ""))
            tags = list(entry.get("tags") or [])
            malware = entry.get("malware_printable") or entry.get("malware")
            if malware and malware not in tags:
                tags.append(malware)
            # threat_type / malware as extra metadata
            confidence_raw = entry.get("confidence_level")
            confidence = 0.6
            try:
                if confidence_raw is not None:
                    confidence = round(float(confidence_raw) / 100.0, 3)
            except (TypeError, ValueError):
                confidence = 0.6
            records.append(
                {
                    "source": "threatfox",
                    "event_id": str(entry.get("id") or ""),
                    "event_info": malware or "threatfox",
                    "indicator_kind": kind,
                    "value": value,
                    "tags": tags,
                    "confidence": confidence,
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen") or entry.get("first_seen"),
                    "raw": entry,
                }
            )
        return records

    # ------------------------------------------------------------------
    # Generic fan-out
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch from one or more abuse.ch sources.

        ``scope`` shape:
            {"sources": ["urlhaus", "malwarebazaar", "threatfox"],
             "urlhaus_limit": 100, "mb_limit": 100, "threatfox_days": 1}

        If ``sources`` is omitted, all three are fetched.
        """
        if not self.healthy:
            logger.info("abuse.ch connector not healthy; returning empty")
            return []

        scope = scope or {}
        sources = scope.get("sources") or ["urlhaus", "malwarebazaar", "threatfox"]
        results: List[Dict[str, Any]] = []
        if "urlhaus" in sources:
            results.extend(self.fetch_urlhaus(limit=int(scope.get("urlhaus_limit", 100))))
        if "malwarebazaar" in sources:
            results.extend(self.fetch_malwarebazaar(limit=int(scope.get("mb_limit", 100))))
        if "threatfox" in sources:
            results.extend(self.fetch_threatfox(days=int(scope.get("threatfox_days", 1))))
        return results
