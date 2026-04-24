"""IOC auto-enrichment orchestrator for Sheshnaag V4 Threat Intel Fabric.

Fans a new :class:`~app.models.malware_lab.IndicatorArtifact` out to every
configured intel connector, collects each source's verdict, computes a
weighted-consensus score, and persists the results back into the
indicator's ``payload`` column under two keys:

  * ``enrichment`` — list of ``{source, verdict, confidence, ts}`` rows.
  * ``enrichment_consensus`` — float in ``[0.0, 1.0]`` summarizing the
    votes across sources. Malicious verdicts are weighted higher than
    suspicious / unknown verdicts.

See ``docs/SHESHNAAG_V4_ARCHITECTURE.md`` Pillar 3 §3.4.
"""

from __future__ import annotations

import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.malware_lab import IndicatorArtifact
from app.models.v2 import Tenant

logger = logging.getLogger(__name__)

# Map an indicator_kind onto the scope dict each connector's ``fetch`` expects.
# Connectors consume a uniform ``{"iocs": [{"kind", "value"}, ...]}`` scope
# where they support it, which is the ergonomic norm in Sheshnaag V4 for
# per-indicator lookups.
_DEFAULT_TIMEOUT_SECONDS = 20.0

#: Per-verdict weight used in the consensus calculation. ``malicious`` votes
#: are worth 1.0, ``suspicious`` 0.5, ``clean`` 0.0. Sources report
#: a numeric confidence in ``[0, 1]``; we blend weight × confidence.
_VERDICT_WEIGHT: Dict[str, float] = {
    "malicious": 1.0,
    "suspicious": 0.5,
    "clean": 0.0,
    "unknown": 0.0,
}


def _now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def _discover_connectors() -> List[Any]:
    """Instantiate every registered IOC connector class.

    The registry lives in :mod:`app.ingestion.misp_connector` (a parallel
    registry to the CVE-advisory one) and is populated by the connector
    modules' side-effecting imports in :mod:`app.ingestion`.
    """

    # Defer import so a unit test can monkey-patch the registry without
    # touching every connector module at import time.
    from app.ingestion.misp_connector import get_registered_ioc_connectors

    instances: List[Any] = []
    for name, cls in get_registered_ioc_connectors().items():
        try:
            instances.append(cls())
        except Exception:  # pragma: no cover — defensive
            logger.warning("Failed to instantiate IOC connector %r", name, exc_info=True)
    return instances


def _classify_verdict(record: Dict[str, Any]) -> str:
    """Translate a connector's normalized record into a verdict label."""

    if not isinstance(record, dict):
        return "unknown"
    # VirusTotal-style: look inside ``stats`` if present.
    stats = record.get("stats") or {}
    if isinstance(stats, dict) and stats:
        mal = int(stats.get("malicious") or 0)
        sus = int(stats.get("suspicious") or 0)
        if mal >= 5:
            return "malicious"
        if mal >= 1 or sus >= 3:
            return "suspicious"
        if sus >= 1:
            return "suspicious"
        return "clean"
    # Confidence-only sources (MISP / OTX / abuse.ch): use the normalized
    # float ``confidence`` they return.
    conf = record.get("confidence")
    if isinstance(conf, (int, float)):
        if conf >= 0.7:
            return "malicious"
        if conf >= 0.4:
            return "suspicious"
        return "clean"
    return "unknown"


def _verdict_record(source: str, raw: Any) -> Optional[Dict[str, Any]]:
    """Collapse a connector's raw response into a single verdict entry.

    Each connector returns ``List[Dict]``. We keep the highest-confidence row
    per source because fan-out is one-indicator-at-a-time; callers do not
    need the full multi-record wire shape beyond the summary.
    """

    if raw is None:
        return None
    rows: List[Dict[str, Any]]
    if isinstance(raw, list):
        rows = [r for r in raw if isinstance(r, dict)]
    elif isinstance(raw, dict):
        rows = [raw]
    else:
        return None

    if not rows:
        return None

    # Pick the row with the highest ``confidence``; fall back to the first.
    rows.sort(key=lambda r: float(r.get("confidence") or 0.0), reverse=True)
    top = rows[0]
    verdict = _classify_verdict(top)
    return {
        "source": source,
        "verdict": verdict,
        "confidence": float(top.get("confidence") or 0.0),
        "ts": _now_iso(),
        "tags": list(top.get("tags") or []),
    }


def _consensus_score(verdicts: Iterable[Dict[str, Any]]) -> float:
    """Compute a weighted consensus score in ``[0.0, 1.0]``.

    Each verdict contributes ``weight(verdict) * confidence``. The final
    score is the average of those weighted contributions across *all*
    sources (not just contributing ones) — a single malicious hit among
    four sources should not saturate to 1.0, reflecting the design in
    Pillar 3 §3.4.
    """

    verdicts = list(verdicts)
    if not verdicts:
        return 0.0
    total = 0.0
    for v in verdicts:
        w = _VERDICT_WEIGHT.get(v.get("verdict", "unknown"), 0.0)
        c = float(v.get("confidence") or 0.0)
        # Weight dominates; a ``malicious`` verdict from a source that
        # returned no confidence number still counts for ~0.5.
        contribution = w if c == 0.0 and w >= 1.0 else w * max(c, 0.25 if w > 0 else 0.0)
        total += contribution
    return round(min(1.0, total / len(verdicts)), 3)


class IocEnrichment:
    """Auto-enrichment fan-out across healthy intel connectors."""

    def __init__(
        self,
        session: Session,
        connectors: Optional[List[Any]] = None,
        *,
        max_workers: int = 4,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._session = session
        if connectors is None:
            connectors = _discover_connectors()
        # Only keep connectors exposing ``healthy == True``. An unhealthy
        # connector has no credentials / no base URL / is otherwise unable
        # to answer; calling it is wasteful and pollutes the consensus.
        self._connectors = [
            c for c in connectors
            if getattr(c, "healthy", False)
            and callable(getattr(c, "fetch", None))
        ]
        self._max_workers = max(1, int(max_workers))
        self._timeout = float(timeout_seconds)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def active_connectors(self) -> List[str]:
        return [getattr(c, "name", c.__class__.__name__) for c in self._connectors]

    def enrich(self, indicator: IndicatorArtifact) -> Dict[str, Any]:
        """Fan out one indicator to every healthy connector in parallel.

        Returns a dict shaped ``{indicator_id, verdicts, consensus}``.
        Side-effect: writes ``enrichment`` and ``enrichment_consensus`` onto
        ``indicator.payload`` and flushes the session.
        """

        scope = self._scope_for_indicator(indicator)

        verdicts: List[Dict[str, Any]] = []
        if self._connectors:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self._max_workers
            ) as executor:
                futures = {
                    executor.submit(self._safe_fetch, conn, scope): conn
                    for conn in self._connectors
                }
                for future in concurrent.futures.as_completed(
                    futures, timeout=self._timeout * max(1, len(futures))
                ):
                    conn = futures[future]
                    source = getattr(conn, "name", conn.__class__.__name__)
                    try:
                        raw = future.result(timeout=self._timeout)
                    except Exception:  # pragma: no cover — defensive
                        logger.warning(
                            "IOC enrichment failed for source %r", source, exc_info=True
                        )
                        continue
                    record = _verdict_record(source, raw)
                    if record is not None:
                        verdicts.append(record)

        consensus = _consensus_score(verdicts)

        payload = dict(indicator.payload or {})
        payload["enrichment"] = verdicts
        payload["enrichment_consensus"] = consensus
        payload["enrichment_last_run_at"] = _now_iso()
        indicator.payload = payload
        # Nudge SQLAlchemy to notice the mutation on the JSON column.
        try:
            from sqlalchemy.orm.attributes import flag_modified

            flag_modified(indicator, "payload")
        except Exception:  # pragma: no cover
            pass

        self._session.flush()

        return {
            "indicator_id": indicator.id,
            "verdicts": verdicts,
            "consensus": consensus,
            "sources": self.active_connectors,
        }

    def enrich_case(self, tenant: Tenant, case_id: int) -> Dict[str, Any]:
        """Enrich every indicator attached to ``case_id`` under ``tenant``."""

        indicators = (
            self._session.query(IndicatorArtifact)
            .filter(
                IndicatorArtifact.tenant_id == tenant.id,
                IndicatorArtifact.analysis_case_id == case_id,
            )
            .all()
        )
        results: Dict[int, Dict[str, Any]] = {}
        for indicator in indicators:
            results[indicator.id] = self.enrich(indicator)
        return {
            "tenant_id": tenant.id,
            "case_id": case_id,
            "count": len(results),
            "results": results,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _scope_for_indicator(indicator: IndicatorArtifact) -> Dict[str, Any]:
        """Produce the per-indicator scope dict accepted by every IOC connector.

        The uniform shape is ``{"iocs": [{"kind", "value"}], "single": True}``
        — connectors that only accept their richer native scope (e.g. MISP
        /events/restSearch) will degrade to a no-op because no matching
        ``iocs`` key is in their expected shape, which is the safer default
        for a fan-out call.
        """

        return {
            "iocs": [
                {
                    "kind": (indicator.indicator_kind or "").lower(),
                    "value": indicator.value,
                }
            ],
            "single": True,
        }

    def _safe_fetch(self, connector: Any, scope: Dict[str, Any]) -> Any:
        """Call ``connector.fetch(scope)`` with conservative exception handling."""

        try:
            return connector.fetch(scope)
        except TypeError:
            # Older connector surface: fetch() takes no args.
            try:
                return connector.fetch()
            except Exception:
                logger.warning(
                    "IOC connector %r fetch() raised",
                    getattr(connector, "name", connector),
                    exc_info=True,
                )
                return None
        except Exception:
            logger.warning(
                "IOC connector %r fetch(scope) raised",
                getattr(connector, "name", connector),
                exc_info=True,
            )
            return None


__all__ = ["IocEnrichment"]
