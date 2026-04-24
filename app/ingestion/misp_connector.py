"""MISP intel connector -- pulls events and extracts IOCs.

Normalizes MISP attributes into the shared IOC record shape used by the
V4 Threat Intel Fabric.  See docs/SHESHNAAG_V4_ARCHITECTURE.md Pillar 3.

Environment:
    MISP_URL  -- base URL of the MISP instance (e.g. https://misp.example.org)
    MISP_KEY  -- API key (sent verbatim in the ``Authorization`` header)
"""

from __future__ import annotations

import logging
import os
from typing import Any, ClassVar, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IOC connector registry (parallel to FeedConnector's CVE-advisory registry)
# ---------------------------------------------------------------------------

_IOC_CONNECTOR_REGISTRY: Dict[str, type] = {}


def register_ioc_connector(cls: type) -> type:
    """Class decorator that registers an IOC intel connector subclass."""
    if not getattr(cls, "name", None):
        raise ValueError(
            f"IOC connector {cls.__name__} must define a 'name' class attribute"
        )
    _IOC_CONNECTOR_REGISTRY[cls.name] = cls
    logger.debug("Registered IOC intel connector: %s", cls.name)
    return cls


def get_ioc_connector(name: str) -> Optional[type]:
    return _IOC_CONNECTOR_REGISTRY.get(name)


def get_registered_ioc_connectors() -> Dict[str, type]:
    return dict(_IOC_CONNECTOR_REGISTRY)


# ---------------------------------------------------------------------------
# MISP attribute-type → normalized indicator_kind mapping
# ---------------------------------------------------------------------------

_MISP_TYPE_MAP: Dict[str, str] = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "domain|ip": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
    "btc": "btc",
    "yara": "yara",
    "mutex": "mutex",
    "regkey": "regkey",
    "user-agent": "user_agent",
}


def _map_indicator_kind(misp_type: str) -> str:
    return _MISP_TYPE_MAP.get(misp_type, misp_type or "unknown")


def _extract_tags(raw: Dict[str, Any]) -> List[str]:
    """Flatten both event-level and attribute-level tag lists."""
    tags: List[str] = []
    for tag in raw.get("Tag") or []:
        name = tag.get("name") if isinstance(tag, dict) else None
        if name:
            tags.append(name)
    return tags


@register_ioc_connector
class MISPConnector:
    """Pulls events and attributes from a MISP instance."""

    name: ClassVar[str] = "misp"
    display_name: ClassVar[str] = "MISP"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://www.misp-project.org/"
    default_timeout_seconds: ClassVar[float] = 30.0

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._base_url = (base_url or os.getenv("MISP_URL") or "").rstrip("/")
        self._api_key = api_key or os.getenv("MISP_KEY") or ""
        self._session = session or requests.Session()
        self._timeout = timeout or self.default_timeout_seconds

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def healthy(self) -> bool:
        return bool(self._base_url and self._api_key)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch normalized IOC records from MISP ``/events/restSearch``.

        ``scope`` accepts optional filters forwarded to MISP:
            - ``limit`` (int)
            - ``page`` (int)
            - ``tags`` (list[str])
            - ``since`` (ISO date or relative, e.g. ``"7d"``)
            - ``type`` (MISP attribute type filter)
        """
        if not self.healthy:
            logger.info("MISP connector not healthy (env missing); returning empty")
            return []

        scope = scope or {}
        payload: Dict[str, Any] = {
            "returnFormat": "json",
            "limit": int(scope.get("limit", 100)),
        }
        for key in ("page", "tags", "type", "eventid", "category"):
            if scope.get(key) is not None:
                payload[key] = scope[key]
        if scope.get("since") is not None:
            payload["timestamp"] = scope["since"]

        url = f"{self._base_url}/events/restSearch"
        try:
            resp = self._session.post(
                url,
                headers=self._headers(),
                json=payload,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            logger.warning("MISP request failed: %s", exc)
            return []

        if resp.status_code >= 400:
            logger.warning(
                "MISP returned status %s for %s: %s",
                resp.status_code,
                url,
                resp.text[:200] if hasattr(resp, "text") else "",
            )
            return []

        try:
            body = resp.json()
        except ValueError as exc:
            logger.warning("MISP response not JSON: %s", exc)
            return []

        return self._normalize_events(body)

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    def _normalize_events(self, body: Any) -> List[Dict[str, Any]]:
        """Flatten MISP's ``{response: [{Event: {...}}, ...]}`` into IOC rows."""
        records: List[Dict[str, Any]] = []

        if isinstance(body, dict):
            events_wrapper = body.get("response", body)
        else:
            events_wrapper = body

        if not isinstance(events_wrapper, list):
            return records

        for item in events_wrapper:
            event = item.get("Event") if isinstance(item, dict) else None
            if not isinstance(event, dict):
                continue

            event_id = str(event.get("id") or event.get("uuid") or "")
            event_info = event.get("info") or ""
            event_tags = _extract_tags(event)

            attributes = event.get("Attribute") or []
            for attr in attributes:
                if not isinstance(attr, dict):
                    continue
                value = attr.get("value")
                if not value:
                    continue
                attr_type = attr.get("type", "")
                kind = _map_indicator_kind(attr_type)
                attr_tags = _extract_tags(attr)

                record = {
                    "source": "misp",
                    "event_id": event_id,
                    "event_info": event_info,
                    "indicator_kind": kind,
                    "value": str(value),
                    "tags": list({*event_tags, *attr_tags}),
                    "confidence": self._confidence_from(event, attr),
                    "first_seen": attr.get("first_seen") or event.get("date"),
                    "last_seen": attr.get("last_seen")
                    or attr.get("timestamp")
                    or event.get("timestamp"),
                    "raw": attr,
                }
                records.append(record)

            # Also fold in shadow / object attributes if present
            for obj in event.get("Object") or []:
                if not isinstance(obj, dict):
                    continue
                for attr in obj.get("Attribute") or []:
                    if not isinstance(attr, dict):
                        continue
                    value = attr.get("value")
                    if not value:
                        continue
                    records.append(
                        {
                            "source": "misp",
                            "event_id": event_id,
                            "event_info": event_info,
                            "indicator_kind": _map_indicator_kind(
                                attr.get("type", "")
                            ),
                            "value": str(value),
                            "tags": list({*event_tags, *_extract_tags(attr)}),
                            "confidence": self._confidence_from(event, attr),
                            "first_seen": attr.get("first_seen")
                            or event.get("date"),
                            "last_seen": attr.get("last_seen")
                            or attr.get("timestamp")
                            or event.get("timestamp"),
                            "raw": attr,
                        }
                    )

        return records

    @staticmethod
    def _confidence_from(event: Dict[str, Any], attr: Dict[str, Any]) -> float:
        """Map MISP threat_level_id (1..4) + to_ids flag to a 0..1 score."""
        try:
            threat_level = int(event.get("threat_level_id", 4))
        except (TypeError, ValueError):
            threat_level = 4
        base = {1: 0.9, 2: 0.75, 3: 0.55, 4: 0.3}.get(threat_level, 0.3)
        if attr.get("to_ids") in (True, "1", 1):
            base = min(1.0, base + 0.1)
        return round(base, 2)
