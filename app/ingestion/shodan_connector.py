"""Shodan REST API connector.

Normalizes Shodan host + search + DNS lookups into the shared IOC record
shape used by the V4 Threat Intel Fabric.

Environment:
    SHODAN_API_KEY  -- Shodan API key (sent as ``?key={API_KEY}`` query param).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)

SHODAN_BASE_URL = "https://api.shodan.io"


def _confidence_from_host(body: Dict[str, Any]) -> float:
    """A coarse confidence score derived from Shodan host payload.

    Heuristic: more open ports + presence of vulnerabilities → higher score.
    We cap at 0.9 because Shodan scans are observational, not adjudicative.
    """
    ports = body.get("ports") or []
    vulns = body.get("vulns") or {}
    vuln_count = len(vulns) if isinstance(vulns, (list, dict)) else 0
    base = 0.3
    if ports:
        base += min(0.3, 0.03 * len(ports))
    if vuln_count:
        base += min(0.3, 0.05 * vuln_count)
    return round(min(0.9, base), 3)


@register_ioc_connector
class ShodanConnector:
    """Wraps Shodan REST API as an IOC intel connector."""

    name: ClassVar[str] = "shodan"
    display_name: ClassVar[str] = "Shodan"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://www.shodan.io/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = SHODAN_BASE_URL,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._api_key = api_key or os.getenv("SHODAN_API_KEY") or ""
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

    # ------------------------------------------------------------------
    # HTTP with rate-limit handling
    # ------------------------------------------------------------------

    def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None
        url = f"{self._base_url}{path}"
        merged: Dict[str, Any] = {"key": self._api_key}
        if params:
            merged.update(params)

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.get(
                    url,
                    params=merged,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Shodan request error (attempt %d/%d) for %s: %s",
                    attempt, self._max_retries, path, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "Shodan rate limited (attempt %d/%d) for %s",
                    attempt, self._max_retries, path,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 404:
                logger.info("Shodan 404 for %s", path)
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "Shodan %s for %s (attempt %d/%d)",
                    resp.status_code, path, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "Shodan client error %s for %s", resp.status_code, path
                )
                return None

            try:
                return resp.json()
            except ValueError:
                logger.warning("Shodan response not JSON for %s", path)
                return None

        return None

    # ------------------------------------------------------------------
    # Per-kind lookups
    # ------------------------------------------------------------------

    def fetch_host(self, ip: str) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        body = self._get(f"/shodan/host/{ip}")
        if not body:
            return None
        return self._normalize_host(body, ip=ip)

    def fetch_search(
        self,
        query: str,
        *,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if not query:
            return []
        body = self._get(
            "/shodan/host/search",
            params={"query": query, "limit": int(limit)},
        )
        if not body:
            return []
        matches = body.get("matches") if isinstance(body, dict) else None
        if not isinstance(matches, list):
            return []
        records: List[Dict[str, Any]] = []
        for match in matches[: max(0, int(limit))]:
            if not isinstance(match, dict):
                continue
            ip = match.get("ip_str") or match.get("ip")
            if not ip:
                continue
            records.append(self._normalize_match(match, ip=str(ip)))
        return records

    def fetch_dns(self, domain: str) -> List[Dict[str, Any]]:
        """Resolve a domain to its DNS A/AAAA records via ``/dns/domain``."""
        if not domain:
            return []
        body = self._get(f"/dns/domain/{domain}")
        if not body:
            return []
        raw_data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(raw_data, list):
            return []

        records: List[Dict[str, Any]] = []
        tags = list(body.get("tags") or [])
        for entry in raw_data:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if not value:
                continue
            rtype = (entry.get("type") or "").upper()
            if rtype in ("A", "AAAA"):
                kind = "ip"
            elif rtype == "CNAME":
                kind = "domain"
            elif rtype == "MX":
                kind = "domain"
            elif rtype == "NS":
                kind = "domain"
            elif rtype == "TXT":
                kind = "txt"
            else:
                kind = rtype.lower() or "dns"
            records.append(
                {
                    "source": "shodan",
                    "indicator_kind": kind,
                    "value": str(value),
                    "confidence": 0.4,
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "labels": [rtype] if rtype else [],
                    "tags": sorted({*tags, rtype}) if rtype else list(tags),
                    "payload": {
                        "domain": domain,
                        "record_type": rtype,
                        "subdomain": entry.get("subdomain"),
                        "raw": entry,
                    },
                }
            )
        return records

    # ------------------------------------------------------------------
    # Generic fan-out
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch records for one or more Shodan inputs.

        ``scope`` shape:
            - ``{"hosts": ["1.2.3.4", ...]}`` -- host lookups
            - ``{"searches": ["apache country:US", ...], "limit": 50}``
            - ``{"domains": ["example.com", ...]}`` -- DNS lookups
        Any combination of the three is supported.
        """
        if not self.healthy:
            logger.info("Shodan connector not healthy (no API key); returning empty")
            return []

        scope = scope or {}
        records: List[Dict[str, Any]] = []

        for ip in scope.get("hosts") or []:
            if not ip:
                continue
            record = self.fetch_host(str(ip))
            if record is not None:
                records.append(record)

        limit = int(scope.get("limit", 100))
        for query in scope.get("searches") or []:
            if not query:
                continue
            records.extend(self.fetch_search(str(query), limit=limit))

        for domain in scope.get("domains") or []:
            if not domain:
                continue
            records.extend(self.fetch_dns(str(domain)))

        return records

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_host(body: Dict[str, Any], *, ip: str) -> Dict[str, Any]:
        ports = list(body.get("ports") or [])
        hostnames = list(body.get("hostnames") or [])
        vulns_raw = body.get("vulns") or {}
        if isinstance(vulns_raw, dict):
            vulns = list(vulns_raw.keys())
        elif isinstance(vulns_raw, list):
            vulns = [str(v) for v in vulns_raw]
        else:
            vulns = []
        tags_raw = body.get("tags") or []
        tags = list(tags_raw) if isinstance(tags_raw, (list, tuple)) else []

        labels: List[str] = []
        org = body.get("org")
        if org:
            labels.append(str(org))
        country = body.get("country_code") or body.get("country_name")
        if country:
            labels.append(str(country))

        combined_tags = sorted({*tags, *labels, *vulns})

        return {
            "source": "shodan",
            "indicator_kind": "ip",
            "value": str(ip),
            "confidence": _confidence_from_host(body),
            "first_seen": body.get("last_update"),
            "last_seen": body.get("last_update"),
            "labels": labels,
            "tags": combined_tags,
            "payload": {
                "ports": ports,
                "hostnames": hostnames,
                "vulns": vulns,
                "org": body.get("org"),
                "isp": body.get("isp"),
                "asn": body.get("asn"),
                "country_code": body.get("country_code"),
                "os": body.get("os"),
                "raw": body,
            },
        }

    @staticmethod
    def _normalize_match(match: Dict[str, Any], *, ip: str) -> Dict[str, Any]:
        hostnames = list(match.get("hostnames") or [])
        port = match.get("port")
        product = match.get("product")
        org = match.get("org")
        labels: List[str] = []
        if product:
            labels.append(str(product))
        if org:
            labels.append(str(org))
        tags = sorted({*labels, *(match.get("tags") or [])})

        return {
            "source": "shodan",
            "indicator_kind": "ip",
            "value": str(ip),
            "confidence": 0.5,
            "first_seen": match.get("timestamp"),
            "last_seen": match.get("timestamp"),
            "labels": labels,
            "tags": tags,
            "payload": {
                "port": port,
                "hostnames": hostnames,
                "product": product,
                "org": org,
                "asn": match.get("asn"),
                "location": match.get("location"),
                "raw": match,
            },
        }
