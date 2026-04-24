"""OpenCTI intel connector -- pulls indicators via GraphQL.

Normalizes OpenCTI ``indicators`` into the shared IOC record shape used
by the V4 Threat Intel Fabric.  See docs/SHESHNAAG_V4_ARCHITECTURE.md
Pillar 3.

Environment:
    OPENCTI_URL    -- base URL of the OpenCTI instance (e.g. https://opencti.example.org)
    OPENCTI_TOKEN  -- API token (sent as ``Authorization: Bearer {token}``)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, ClassVar, Dict, List, Optional

import requests

from app.ingestion.misp_connector import register_ioc_connector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GraphQL query
# ---------------------------------------------------------------------------

INDICATORS_QUERY = """
query Indicators($first: Int, $after: ID, $filters: FilterGroup, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode) {
  indicators(first: $first, after: $after, filters: $filters, orderBy: $orderBy, orderMode: $orderMode) {
    edges {
      node {
        id
        standard_id
        entity_type
        pattern
        pattern_type
        name
        description
        x_opencti_score
        confidence
        valid_from
        valid_until
        created_at
        updated_at
        revoked
        x_opencti_main_observable_type
        objectLabel {
          value
        }
        objectMarking {
          definition
        }
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
  }
}
""".strip()


# ---------------------------------------------------------------------------
# OpenCTI observable-type → normalized indicator_kind mapping
# ---------------------------------------------------------------------------

_OPENCTI_TYPE_MAP: Dict[str, str] = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "hostname": "domain",
    "url": "url",
    "email-addr": "email",
    "email-message": "email",
    "stixfile": "file",
    "file": "file",
    "mutex": "mutex",
    "windows-registry-key": "regkey",
    "user-agent": "user_agent",
    "autonomous-system": "asn",
    "cryptocurrency-wallet": "btc",
}


def _map_indicator_kind(observable_type: str, pattern: str = "") -> str:
    """Map OpenCTI ``x_opencti_main_observable_type`` into normalized kind.

    Falls back to inspecting the STIX pattern for hash-specific kinds
    (md5/sha1/sha256) since those all share ``file`` as their observable.
    """
    lower = (observable_type or "").lower()
    mapped = _OPENCTI_TYPE_MAP.get(lower)
    if mapped == "file" and pattern:
        pattern_l = pattern.lower()
        if "hashes.'sha-256'" in pattern_l or "hashes.sha256" in pattern_l:
            return "sha256"
        if "hashes.'sha-1'" in pattern_l or "hashes.sha1" in pattern_l:
            return "sha1"
        if "hashes.md5" in pattern_l:
            return "md5"
        if "hashes.'sha-512'" in pattern_l:
            return "sha512"
    if mapped:
        return mapped
    return lower or "unknown"


def _extract_value_from_pattern(pattern: str) -> Optional[str]:
    """Extract the literal value from a STIX2 pattern like ``[ipv4-addr:value = '1.2.3.4']``.

    The target literal is the one immediately following the ``=`` operator;
    we skip over any earlier quoted tokens (e.g. hash-key names like
    ``'SHA-256'`` inside ``file:hashes.'SHA-256' = '...'``).
    """
    if not pattern:
        return None
    # Prefer the literal that follows the ``=`` operator.
    eq_idx = pattern.find("=")
    search_from = eq_idx + 1 if eq_idx >= 0 else 0
    try:
        start = pattern.index("'", search_from)
        end = pattern.index("'", start + 1)
        return pattern[start + 1 : end]
    except ValueError:
        pass
    # Fallback: first quoted literal anywhere.
    try:
        start = pattern.index("'")
        end = pattern.index("'", start + 1)
        return pattern[start + 1 : end]
    except ValueError:
        return pattern or None


@register_ioc_connector
class OpenCTIConnector:
    """Pulls indicators from an OpenCTI instance via GraphQL."""

    name: ClassVar[str] = "opencti"
    display_name: ClassVar[str] = "OpenCTI"
    category: ClassVar[str] = "intel"
    source_url: ClassVar[str] = "https://www.opencti.io/"
    default_timeout_seconds: ClassVar[float] = 30.0
    default_max_retries: ClassVar[int] = 3
    default_backoff_seconds: ClassVar[float] = 2.0

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_seconds: Optional[float] = None,
        sleep_fn=time.sleep,
    ) -> None:
        self._base_url = (base_url or os.getenv("OPENCTI_URL") or "").rstrip("/")
        self._token = token or os.getenv("OPENCTI_TOKEN") or ""
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
        return bool(self._base_url and self._token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # GraphQL transport with rate-limit handling
    # ------------------------------------------------------------------

    def _graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.healthy:
            return None

        url = f"{self._base_url}/graphql"
        payload = {"query": query, "variables": variables or {}}

        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._session.post(
                    url,
                    headers=self._headers(),
                    json=payload,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "OpenCTI request error (attempt %d/%d): %s",
                    attempt, self._max_retries, exc,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code == 429:
                logger.warning(
                    "OpenCTI rate limited (attempt %d/%d)",
                    attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 500:
                logger.warning(
                    "OpenCTI %s (attempt %d/%d)",
                    resp.status_code, attempt, self._max_retries,
                )
                if attempt < self._max_retries:
                    self._sleep(self._backoff * attempt)
                continue

            if resp.status_code >= 400:
                logger.warning(
                    "OpenCTI client error %s: %s",
                    resp.status_code,
                    resp.text[:200] if hasattr(resp, "text") else "",
                )
                return None

            try:
                body = resp.json()
            except ValueError:
                logger.warning("OpenCTI response not JSON")
                return None

            if isinstance(body, dict) and body.get("errors"):
                logger.warning("OpenCTI GraphQL errors: %s", body.get("errors"))
                return None

            return body

        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self, scope: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Fetch normalized IOC records from OpenCTI.

        ``scope`` accepts optional filters forwarded to the GraphQL query:
            - ``first`` (int, page size; default 100)
            - ``after`` (str, opaque cursor)
            - ``created_since`` (ISO date) -- filter on ``created_at``
            - ``labels`` (list[str]) -- OR-match on ``objectLabel``
            - ``min_score`` (int 0..100) -- filter on ``x_opencti_score``
        """
        if not self.healthy:
            logger.info("OpenCTI connector not healthy (env missing); returning empty")
            return []

        scope = scope or {}
        variables: Dict[str, Any] = {
            "first": int(scope.get("first", 100)),
            "orderBy": "created_at",
            "orderMode": "desc",
        }
        if scope.get("after"):
            variables["after"] = scope["after"]

        filters: List[Dict[str, Any]] = []
        if scope.get("created_since"):
            filters.append(
                {
                    "key": "created_at",
                    "values": [scope["created_since"]],
                    "operator": "gt",
                    "mode": "or",
                }
            )
        labels = scope.get("labels") or []
        if labels:
            filters.append(
                {
                    "key": "objectLabel",
                    "values": list(labels),
                    "operator": "eq",
                    "mode": "or",
                }
            )
        if scope.get("min_score") is not None:
            filters.append(
                {
                    "key": "x_opencti_score",
                    "values": [str(int(scope["min_score"]))],
                    "operator": "gte",
                    "mode": "or",
                }
            )
        if filters:
            variables["filters"] = {
                "mode": "and",
                "filters": filters,
                "filterGroups": [],
            }

        body = self._graphql(INDICATORS_QUERY, variables)
        if not body:
            return []

        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            return []
        indicators = data.get("indicators") or {}
        edges = indicators.get("edges") if isinstance(indicators, dict) else None
        if not isinstance(edges, list):
            return []

        records: List[Dict[str, Any]] = []
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            node = edge.get("node")
            if not isinstance(node, dict):
                continue
            record = self._normalize_node(node)
            if record is not None:
                records.append(record)
        return records

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_node(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pattern = node.get("pattern") or ""
        observable = node.get("x_opencti_main_observable_type") or ""
        kind = _map_indicator_kind(observable, pattern)

        value = node.get("name") or _extract_value_from_pattern(pattern)
        if not value:
            return None

        labels: List[str] = []
        for lbl in node.get("objectLabel") or []:
            if isinstance(lbl, dict) and lbl.get("value"):
                labels.append(lbl["value"])

        tags: List[str] = list(labels)
        for mark in node.get("objectMarking") or []:
            if isinstance(mark, dict) and mark.get("definition"):
                tags.append(mark["definition"])

        score = node.get("x_opencti_score")
        try:
            score_int = int(score) if score is not None else None
        except (TypeError, ValueError):
            score_int = None
        if score_int is None:
            confidence_src = node.get("confidence")
            try:
                score_int = int(confidence_src) if confidence_src is not None else 50
            except (TypeError, ValueError):
                score_int = 50
        confidence = max(0.0, min(1.0, round(score_int / 100.0, 3)))

        return {
            "source": "opencti",
            "indicator_kind": kind,
            "value": str(value),
            "confidence": confidence,
            "first_seen": node.get("valid_from") or node.get("created_at"),
            "last_seen": node.get("valid_until") or node.get("updated_at"),
            "labels": labels,
            "tags": sorted(set(tags)),
            "payload": {
                "id": node.get("id"),
                "standard_id": node.get("standard_id"),
                "entity_type": node.get("entity_type"),
                "pattern": pattern,
                "pattern_type": node.get("pattern_type"),
                "description": node.get("description"),
                "revoked": node.get("revoked"),
                "x_opencti_score": score_int,
                "observable_type": observable,
                "raw": node,
            },
        }
