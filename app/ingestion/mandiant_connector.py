"""Mandiant Advantage Threat Intelligence connector.

Normalizes Mandiant ``/indicator`` + ``/actor/{id}`` + ``/malware/{id}``
responses into the shared IOC record shape used by the V4 Threat Intel
Fabric.

Authentication can be supplied in two ways:

1. ``MANDIANT_ACCESS_TOKEN``  -- a pre-issued bearer token, used directly
   in the ``Authorization`` header.
2. ``MANDIANT_KEY`` + ``MANDIANT_SECRET`` -- HTTP Basic-auth credentials
   exchanged for a bearer token via ``POST /token`` on first use.  Tokens
   are cached in-memory for the lifetime of the connector instance.

All requests also send ``X-App-Name: sheshnaag`` per Mandiant convention.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional, Tuple

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)

MANDIANT_BASE_URL = "https://api.intelligence.mandiant.com/v4"
MANDIANT_APP_NAME = "sheshnaag"

# Mandiant "type" → normalized indicator_kind
_MANDIANT_TYPE_MAP: Dict[str, str] = {
    "ipv4": "ip",
    "ipv6": "ip",
    "fqdn": "domain",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email",
}


def _map_indicator_kind(mandiant_type: str) -> str:
    return _MANDIANT_TYPE_MAP.get((mandiant_type or "").lower(), (mandiant_type or "unknown").lower())


@register_ioc_connector
class MandiantConnector:
    """Pulls indicators + actor/malware context from Mandiant Advantage."""

    name: ClassVar[str] = "mandiant"
    display_name: ClassVar[str] = "Mandiant Advantage"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://advantage.mandiant.com/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        access_token: Optional[str] = None,
        *,
        key: Optional[str] = None,
        secret: Optional[str] = None,
        base_url: str = MANDIANT_BASE_URL,
        app_name: str = MANDIANT_APP_NAME,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._access_token = access_token or os.getenv("MANDIANT_ACCESS_TOKEN") or ""
        self._key = key or os.getenv("MANDIANT_KEY") or ""
        self._secret = secret or os.getenv("MANDIANT_SECRET") or ""
        self._base_url = base_url.rstrip("/")
        self._app_name = app_name
        self._session = session or requests.Session()
        self._timeout = timeout or self.default_timeout_seconds
        self._max_retries = max_retries or self.default_max_retries
        self._backoff = backoff_seconds or self.default_backoff_seconds
        self._sleep = sleep_fn
        self._cached_token: Optional[str] = self._access_token or None

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def healthy(self) -> bool:
        return bool(self._access_token or (self._key and self._secret))

    # ------------------------------------------------------------------
    # Token exchange (key+secret → bearer)
    # ------------------------------------------------------------------

    def _ensure_token(self) -> Optional[str]:
        """Return a bearer token, exchanging key+secret if needed."""
        if self._cached_token:
            return self._cached_token
        if not (self._key and self._secret):
            return None

        url = f"{self._base_url}/token"
        try:
            resp = self._session.post(
                url,
                auth=(self._key, self._secret),
                headers={
                    "Accept": "application/json",
                    "X-App-Name": self._app_name,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={"grant_type": "client_credentials"},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            logger.warning("Mandiant token exchange failed: %s", exc)
            return None

        if resp.status_code >= 400:
            logger.warning(
                "Mandiant token exchange status %s: %s",
                resp.status_code,
                resp.text[:200] if hasattr(resp, "text") else "",
            )
            return None

        try:
            body = resp.json()
        except ValueError:
            logger.warning("Mandiant token response not JSON")
            return None

        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            logger.warning("Mandiant token response missing access_token")
            return None

        self._cached_token = token
        return token

    # ------------------------------------------------------------------
    # HTTP with rate-limit handling
    # ------------------------------------------------------------------

    def _headers(self, token: str) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "X-App-Name": self._app_name,
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None
        token = self._ensure_token()
        if not token:
            return None

        url = f"{self._base_url}{path}"
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.request(
                    method,
                    url,
                    headers=self._headers(token),
                    params=params,
                    json=json_body,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Mandiant request error (attempt %d/%d) for %s: %s",
                    attempt, self._max_retries, path, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "Mandiant rate limited (attempt %d/%d) for %s",
                    attempt, self._max_retries, path,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 401:
                # Token may have expired; drop cache and retry once.
                logger.info("Mandiant 401 for %s -- refreshing token", path)
                self._cached_token = None if not self._access_token else self._cached_token
                if attempt < self._max_retries and not self._access_token:
                    token = self._ensure_token() or ""
                    if not token:
                        return None
                    continue
                return None

            if resp.status_code == 404:
                logger.info("Mandiant 404 for %s", path)
                return None

            if resp.status_code >= 500:
                logger.warning(
                    "Mandiant %s for %s (attempt %d/%d)",
                    resp.status_code, path, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "Mandiant client error %s for %s", resp.status_code, path
                )
                return None

            try:
                return resp.json()
            except ValueError:
                logger.warning("Mandiant response not JSON for %s", path)
                return None

        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_indicators(
        self,
        *,
        limit: int = 100,
        gte_mscore: Optional[int] = None,
        last_updated: Optional[str] = None,
        include_actors: bool = True,
        include_malware: bool = True,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": int(limit)}
        if gte_mscore is not None:
            params["gte_mscore"] = int(gte_mscore)
        if last_updated:
            params["last_updated"] = last_updated
        if include_actors:
            params["include_actors"] = "true"
        if include_malware:
            params["include_malware"] = "true"

        body = self._request("GET", "/indicator", params=params)
        if not body:
            return []
        indicators = body.get("indicators") if isinstance(body, dict) else None
        if not isinstance(indicators, list):
            return []

        records: List[Dict[str, Any]] = []
        for ind in indicators:
            if not isinstance(ind, dict):
                continue
            record = self._normalize_indicator(ind)
            if record is not None:
                records.append(record)
        return records

    def fetch_actor(self, actor_id: str) -> Optional[Dict[str, Any]]:
        if not actor_id:
            return None
        return self._request("GET", f"/actor/{actor_id}")

    def fetch_malware(self, malware_id: str) -> Optional[Dict[str, Any]]:
        if not malware_id:
            return None
        return self._request("GET", f"/malware/{malware_id}")

    # ------------------------------------------------------------------
    # Generic fetch
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch normalized indicator records from Mandiant.

        ``scope`` shape:
            - ``limit`` (int, default 100)
            - ``gte_mscore`` (int 0..100)
            - ``last_updated`` (ISO or unix timestamp)
            - ``include_actors`` (bool, default True)
            - ``include_malware`` (bool, default True)
        """
        if not self.healthy:
            logger.info("Mandiant connector not healthy (env missing); returning empty")
            return []

        scope = scope or {}
        return self.fetch_indicators(
            limit=int(scope.get("limit", 100)),
            gte_mscore=scope.get("gte_mscore"),
            last_updated=scope.get("last_updated"),
            include_actors=bool(scope.get("include_actors", True)),
            include_malware=bool(scope.get("include_malware", True)),
        )

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_indicator(ind: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        value = ind.get("value")
        if not value:
            return None

        mscore_raw = ind.get("mscore")
        try:
            mscore = int(mscore_raw) if mscore_raw is not None else None
        except (TypeError, ValueError):
            mscore = None
        if mscore is None:
            mscore = 50
        confidence = max(0.0, min(1.0, round(mscore / 100.0, 3)))

        kind = _map_indicator_kind(ind.get("type", ""))

        threat_actors: List[Dict[str, Any]] = []
        for actor in ind.get("threat_actors") or ind.get("actors") or []:
            if isinstance(actor, dict):
                threat_actors.append(
                    {
                        "id": actor.get("id"),
                        "name": actor.get("name"),
                        "aliases": actor.get("aliases") or [],
                    }
                )

        malware_families: List[Dict[str, Any]] = []
        for malware in ind.get("malware_families") or ind.get("malware") or []:
            if isinstance(malware, dict):
                malware_families.append(
                    {
                        "id": malware.get("id"),
                        "name": malware.get("name"),
                        "aliases": malware.get("aliases") or [],
                    }
                )

        sources = ind.get("sources") or []
        categories: List[str] = []
        if isinstance(sources, list):
            for src in sources:
                if isinstance(src, dict):
                    for cat in src.get("category") or []:
                        if cat:
                            categories.append(str(cat))

        tags: List[str] = []
        for actor in threat_actors:
            if actor.get("name"):
                tags.append(str(actor["name"]))
        for malware in malware_families:
            if malware.get("name"):
                tags.append(str(malware["name"]))
        for cat in categories:
            tags.append(cat)

        return {
            "source": "mandiant",
            "indicator_kind": kind,
            "value": str(value),
            "confidence": confidence,
            "first_seen": ind.get("first_seen"),
            "last_seen": ind.get("last_seen") or ind.get("last_updated"),
            "labels": list({*categories}),
            "tags": sorted(set(tags)),
            "payload": {
                "id": ind.get("id"),
                "mscore": mscore,
                "type": ind.get("type"),
                "threat_actors": threat_actors,
                "malware_families": malware_families,
                "categories": categories,
                "sources": sources,
                "raw": ind,
            },
        }
