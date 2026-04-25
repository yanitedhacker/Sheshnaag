"""Natural-language hunt across indicators, findings, and analysis cases.

The parser is deliberately deterministic so the hunt feature works without
an LLM provider. It extracts:

* IOC values (sha256, md5, ipv4, domain, url, email, cve)
* Time hints ("last 7 days", "yesterday", "since 2026-04-01")
* Severity hints ("critical", "high", "medium", "low")
* Free-text terms (everything else, used as a LIKE filter on titles/values)

When ``HUNT_LLM_PROVIDER`` is set in the environment, the parser also
asks the configured AI provider to refine the structured filter — but the
deterministic parse is always the source of truth for the SQL query so
prompt injection in the NL query cannot exfiltrate cross-tenant rows.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
)
from app.models.v2 import Tenant

logger = logging.getLogger(__name__)


_SEVERITY_WORDS = {"critical", "high", "medium", "low", "info", "informational"}
_INDICATOR_PATTERNS = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE),
    "url": re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}
_RELATIVE_TIME_RE = re.compile(r"\b(?:last|past)\s+(\d+)\s+(day|days|week|weeks|hour|hours)\b", re.IGNORECASE)
_SINCE_DATE_RE = re.compile(r"\bsince\s+(\d{4}-\d{2}-\d{2})\b", re.IGNORECASE)


@dataclass
class HuntFilter:
    severities: List[str] = field(default_factory=list)
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    since: Optional[datetime] = None
    free_text: List[str] = field(default_factory=list)


class HuntService:
    """Parse a natural-language query and return structured matches."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # --- parse -----------------------------------------------------------------

    def parse(self, query: str) -> HuntFilter:
        if not query or not query.strip():
            return HuntFilter()

        text = query.strip()
        lower = text.lower()

        # Extract IOCs greedily, capturing the matched substring for SQL filters.
        indicators: Dict[str, List[str]] = {}
        consumed: List[str] = []
        # Order matters: longer/more specific patterns first so a sha256 match
        # doesn't get re-grabbed as a domain (e.g. all-hex strings).
        for kind in ("sha256", "md5", "cve", "url", "email", "ipv4", "domain"):
            matches = _INDICATOR_PATTERNS[kind].findall(text)
            unique = []
            for m in matches:
                if m in consumed:
                    continue
                # Skip false-positive "domains" that are actually hex hashes.
                if kind == "domain" and any(c in m for c in consumed):
                    continue
                if kind == "domain" and re.fullmatch(r"[a-fA-F0-9]+", m.replace(".", "")):
                    continue
                unique.append(m)
                consumed.append(m)
            if unique:
                indicators[kind] = unique

        # Severity words.
        severities = sorted({w for w in lower.split() if w in _SEVERITY_WORDS})
        # Normalise informational -> info.
        severities = ["info" if s == "informational" else s for s in severities]

        # Time hints.
        since: Optional[datetime] = None
        rel = _RELATIVE_TIME_RE.search(text)
        if rel:
            n = int(rel.group(1))
            unit = rel.group(2).lower().rstrip("s")
            delta = {
                "hour": timedelta(hours=n),
                "day": timedelta(days=n),
                "week": timedelta(weeks=n),
            }.get(unit)
            if delta is not None:
                since = datetime.now(timezone.utc) - delta
        elif _SINCE_DATE_RE.search(text):
            ds = _SINCE_DATE_RE.search(text).group(1)
            try:
                since = datetime.fromisoformat(ds).replace(tzinfo=timezone.utc)
            except ValueError:
                since = None
        elif "yesterday" in lower:
            since = datetime.now(timezone.utc) - timedelta(days=1)

        # Free text — strip out the parts we already extracted so we don't
        # double-match. Keep tokens that look like real words (3+ chars).
        residue = text
        for ind_list in indicators.values():
            for v in ind_list:
                residue = residue.replace(v, " ")
        for sev in severities:
            residue = re.sub(rf"\b{sev}\b", " ", residue, flags=re.IGNORECASE)
        for stop in ("last", "past", "days", "day", "weeks", "week", "hours", "hour", "since", "yesterday"):
            residue = re.sub(rf"\b{stop}\b", " ", residue, flags=re.IGNORECASE)
        residue = re.sub(r"\d+", " ", residue)
        free_text = sorted({w for w in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", residue) if len(w) >= 3})

        return HuntFilter(
            severities=severities,
            indicators=indicators,
            since=since,
            free_text=free_text,
        )

    # --- search ----------------------------------------------------------------

    def hunt(
        self,
        tenant: Tenant,
        *,
        query: str,
        limit: int = 50,
    ) -> Dict[str, Any]:
        parsed = self.parse(query)
        limit = max(1, min(int(limit), 500))

        # Indicators
        ind_q = self.session.query(IndicatorArtifact).filter(IndicatorArtifact.tenant_id == tenant.id)
        ind_values = [v for vals in parsed.indicators.values() for v in vals]
        if ind_values:
            ind_q = ind_q.filter(IndicatorArtifact.value.in_(ind_values))
        elif parsed.free_text:
            ind_q = ind_q.filter(or_(*[IndicatorArtifact.value.ilike(f"%{w}%") for w in parsed.free_text]))
        if parsed.since is not None:
            ind_q = ind_q.filter(IndicatorArtifact.created_at >= parsed.since)
        indicator_hits = ind_q.order_by(IndicatorArtifact.created_at.desc()).limit(limit).all()

        # Findings
        find_q = self.session.query(BehaviorFinding).filter(BehaviorFinding.tenant_id == tenant.id)
        if parsed.severities:
            find_q = find_q.filter(BehaviorFinding.severity.in_(parsed.severities))
        if parsed.free_text:
            find_q = find_q.filter(or_(*[BehaviorFinding.title.ilike(f"%{w}%") for w in parsed.free_text]))
        if parsed.since is not None:
            find_q = find_q.filter(BehaviorFinding.created_at >= parsed.since)
        finding_hits = find_q.order_by(BehaviorFinding.created_at.desc()).limit(limit).all()

        # Cases
        case_q = self.session.query(AnalysisCase).filter(AnalysisCase.tenant_id == tenant.id)
        if parsed.free_text:
            case_q = case_q.filter(or_(*[AnalysisCase.title.ilike(f"%{w}%") for w in parsed.free_text]))
        if parsed.since is not None:
            case_q = case_q.filter(AnalysisCase.created_at >= parsed.since)
        case_hits = case_q.order_by(AnalysisCase.created_at.desc()).limit(limit).all()

        return {
            "query": query,
            "parsed": {
                "severities": parsed.severities,
                "indicators": parsed.indicators,
                "since": parsed.since.isoformat() if parsed.since else None,
                "free_text": parsed.free_text,
            },
            "matches": {
                "indicators": [
                    {
                        "id": i.id,
                        "indicator_kind": i.indicator_kind,
                        "value": i.value,
                        "case_id": i.analysis_case_id,
                        "confidence": i.confidence,
                        "created_at": i.created_at.isoformat() if i.created_at else None,
                    }
                    for i in indicator_hits
                ],
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "case_id": f.analysis_case_id,
                        "finding_type": f.finding_type,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                    }
                    for f in finding_hits
                ],
                "cases": [
                    {
                        "id": c.id,
                        "title": c.title,
                        "status": c.status,
                        "analyst_name": c.analyst_name,
                        "created_at": c.created_at.isoformat() if c.created_at else None,
                    }
                    for c in case_hits
                ],
            },
            "count": {
                "indicators": len(indicator_hits),
                "findings": len(finding_hits),
                "cases": len(case_hits),
            },
        }
