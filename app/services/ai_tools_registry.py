"""Registry of callable tools exposed to models under capability-policy control.

Phase B closes the Phase A stubs for the read/intel surface
(``fetch_specimen_triage``, ``query_knowledge``, ``pivot_ioc``,
``run_yara_scan``, ``query_intel_feed``) by wiring them to the existing
service layer. Every callable still accepts arbitrary kwargs so the LLM
adapter contract is unchanged, and degrades to a stub-shaped response
when invoked outside of an AIAgentLoop run (so unit tests that drive the
registry directly keep working).

Stubs that remain (``propose_detection``, ``detonate_in_sandbox``,
``export_external``, ``run_authorized_offensive``) are gated by capability
artifacts and intentionally left as no-op shapes until their backing
services land — those are write-side surfaces with policy implications.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    capability: Optional[str]
    callable: Callable[..., Dict[str, Any]]
    tags: tuple = field(default_factory=tuple)
    requires_context: bool = False

    def describe(self) -> Dict[str, Any]:
        """Return the model-facing tool schema."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _echo_hash(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(repr(sorted(payload.items())).encode("utf-8")).hexdigest()[:16]


def _ctx_session(context: Optional[Dict[str, Any]]):
    if not context:
        return None
    return context.get("session")


def _ctx_tenant_id(context: Optional[Dict[str, Any]]) -> Optional[int]:
    if not context:
        return None
    tid = context.get("tenant_id")
    try:
        return int(tid) if tid is not None else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Real tool implementations
# ---------------------------------------------------------------------------


def _fetch_specimen_triage(
    specimen_id: str | int,
    _context: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """Return static triage for a specimen.

    Wraps the existing Specimen + SpecimenRevision rows: pulls the latest
    revision's static_triage JSON, sha256, content_ref, plus tenant-scoped
    metadata and labels. Falls back to a stub shape when no DB context is
    provided so unit tests of the registry can still run.
    """

    session = _ctx_session(_context)
    tenant_id = _ctx_tenant_id(_context)
    base = {
        "tool": "fetch_specimen_triage",
        "specimen_id": specimen_id,
        "fetched_at": time.time(),
    }
    if session is None or tenant_id is None:
        base["triage"] = {
            "kind": "unknown",
            "size_bytes": 0,
            "sha256": None,
            "first_seen": None,
            "tags": [],
            "notes": "No DB context supplied; returning stub shape.",
        }
        return base

    from sqlalchemy import desc

    from app.models.malware_lab import Specimen, SpecimenRevision

    try:
        spec_id = int(specimen_id)
    except (TypeError, ValueError):
        base["error"] = "invalid_specimen_id"
        return base

    spec = (
        session.query(Specimen)
        .filter(Specimen.tenant_id == tenant_id, Specimen.id == spec_id)
        .first()
    )
    if spec is None:
        base["error"] = "specimen_not_found"
        return base
    revision = (
        session.query(SpecimenRevision)
        .filter(SpecimenRevision.specimen_id == spec.id)
        .order_by(desc(SpecimenRevision.revision_number))
        .first()
    )

    static_triage = (revision.static_triage if revision else None) or {}
    quarantine_path = revision.quarantine_path if revision else None
    size_bytes: Optional[int] = None
    if quarantine_path:
        try:
            size_bytes = Path(quarantine_path).stat().st_size
        except OSError:
            size_bytes = None

    base["triage"] = {
        "kind": spec.specimen_kind,
        "name": spec.name,
        "status": spec.status,
        "risk_level": spec.risk_level,
        "size_bytes": size_bytes,
        "sha256": revision.sha256 if revision else None,
        "first_seen": spec.created_at.isoformat() if spec.created_at else None,
        "labels": list(spec.labels or []),
        "tags": list((static_triage.get("tags") or [])),
        "static_triage": static_triage,
        "revision_number": revision.revision_number if revision else None,
        "content_ref": revision.content_ref if revision else None,
    }
    return base


def _query_knowledge(
    query: str,
    k: int = 8,
    _context: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """BM25 + cosine search over the internal knowledge corpus.

    Routes to KnowledgeRetrievalService.search which already implements
    pgvector + BM25 fusion with grounding metadata. When no session is
    available we return an empty hit list with a note so callers can tell
    the search ran vs. wasn't wired.
    """

    session = _ctx_session(_context)
    base = {"tool": "query_knowledge", "query": query, "k": int(k)}
    if session is None:
        base["hits"] = []
        base["note"] = "No DB context supplied; cannot search."
        return base

    from app.core.tenancy import resolve_tenant
    from app.services.knowledge_service import KnowledgeRetrievalService

    tenant_id = _ctx_tenant_id(_context)
    tenant = None
    if tenant_id is not None:
        try:
            tenant = resolve_tenant(session, tenant_id=tenant_id, default_to_demo=False)
        except Exception:
            tenant = None
    try:
        hits = KnowledgeRetrievalService(session).search(
            query, tenant=tenant, limit=max(1, min(int(k), 50))
        )
    except Exception as exc:
        logger.warning("query_knowledge search failed: %s", exc)
        base["hits"] = []
        base["error"] = f"{type(exc).__name__}: {exc}"
        return base

    base["hits"] = hits
    base["count"] = len(hits)
    return base


def _pivot_ioc(
    indicator_value: str,
    _context: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """Return the neighborhood of an IOC in the case graph.

    Walks IndicatorArtifact -> AnalysisCase -> sibling indicators and
    behavior findings citing the same value. The graph rebuilder is left
    untouched (it materialises an edge table); this query is intentionally
    light-weight so the LLM can pivot interactively without a full rebuild.
    """

    session = _ctx_session(_context)
    tenant_id = _ctx_tenant_id(_context)
    base = {"tool": "pivot_ioc", "indicator_value": indicator_value}
    if session is None or tenant_id is None:
        base["neighbors"] = []
        base["note"] = "No DB context supplied."
        return base

    from app.models.malware_lab import (
        AnalysisCase,
        BehaviorFinding,
        IndicatorArtifact,
    )

    matches = (
        session.query(IndicatorArtifact)
        .filter(
            IndicatorArtifact.tenant_id == tenant_id,
            IndicatorArtifact.value == indicator_value,
        )
        .limit(20)
        .all()
    )
    if not matches:
        base["neighbors"] = []
        base["note"] = "indicator_not_found"
        return base

    case_ids = sorted({m.analysis_case_id for m in matches})
    sibling_indicators = (
        session.query(IndicatorArtifact)
        .filter(
            IndicatorArtifact.tenant_id == tenant_id,
            IndicatorArtifact.analysis_case_id.in_(case_ids),
            IndicatorArtifact.value != indicator_value,
        )
        .limit(50)
        .all()
    )
    findings = (
        session.query(BehaviorFinding)
        .filter(
            BehaviorFinding.tenant_id == tenant_id,
            BehaviorFinding.analysis_case_id.in_(case_ids),
        )
        .limit(50)
        .all()
    )
    cases = (
        session.query(AnalysisCase)
        .filter(AnalysisCase.tenant_id == tenant_id, AnalysisCase.id.in_(case_ids))
        .all()
    )

    base["neighbors"] = [
        {
            "kind": "indicator",
            "id": ind.id,
            "indicator_kind": ind.indicator_kind,
            "value": ind.value,
            "case_id": ind.analysis_case_id,
            "confidence": ind.confidence,
        }
        for ind in sibling_indicators
    ] + [
        {
            "kind": "finding",
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "case_id": f.analysis_case_id,
        }
        for f in findings
    ] + [
        {"kind": "case", "id": c.id, "title": c.title, "status": c.status}
        for c in cases
    ]
    base["match_count"] = len(matches)
    base["case_count"] = len(case_ids)
    return base


def _run_yara_scan(
    ruleset_id: str,
    scope: Optional[Dict[str, Any]] = None,
    _context: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """Compile YARA rules from a configurable directory and scan a specimen.

    `ruleset_id` selects a `.yar`/`.yara` file under SHESHNAAG_YARA_RULES_DIR
    (default ./yara-rules). `scope` accepts ``{"specimen_id": int}`` or
    ``{"path": str}`` — when a specimen id is supplied we resolve it via the
    SpecimenRevision.quarantine_path so the LLM never gets to choose a raw
    filesystem path.
    """

    scope = scope or {}
    base: Dict[str, Any] = {"tool": "run_yara_scan", "ruleset_id": ruleset_id, "scope": scope}

    try:
        import yara  # type: ignore
    except ImportError:
        base["matches"] = []
        base["error"] = "yara_python_not_installed"
        return base

    rules_dir = Path(os.getenv("SHESHNAAG_YARA_RULES_DIR", "./yara-rules"))
    candidate = rules_dir / f"{ruleset_id}.yar"
    if not candidate.is_file():
        candidate = rules_dir / f"{ruleset_id}.yara"
    if not candidate.is_file():
        base["matches"] = []
        base["error"] = "ruleset_not_found"
        base["expected_path"] = str(rules_dir / f"{ruleset_id}.yar")
        return base

    # Resolve the target path via the DB so an LLM can't smuggle an arbitrary
    # filesystem read through `scope.path`.
    target_path: Optional[str] = None
    session = _ctx_session(_context)
    tenant_id = _ctx_tenant_id(_context)
    specimen_id = scope.get("specimen_id")
    if session is not None and tenant_id is not None and specimen_id is not None:
        from sqlalchemy import desc

        from app.models.malware_lab import Specimen, SpecimenRevision

        spec = (
            session.query(Specimen)
            .filter(Specimen.tenant_id == tenant_id, Specimen.id == int(specimen_id))
            .first()
        )
        if spec is not None:
            revision = (
                session.query(SpecimenRevision)
                .filter(SpecimenRevision.specimen_id == spec.id)
                .order_by(desc(SpecimenRevision.revision_number))
                .first()
            )
            if revision and revision.quarantine_path:
                target_path = revision.quarantine_path
    if target_path is None:
        # Last resort: allow an explicit path but only if it lives under the
        # configured quarantine root (path-containment, same pattern as the
        # disclosure download fix).
        explicit = scope.get("path")
        quarantine_root = Path(
            os.getenv("SHESHNAAG_QUARANTINE_ROOT", "/tmp/sheshnaag_quarantine")
        ).resolve(strict=False)
        if explicit:
            try:
                resolved = Path(explicit).resolve(strict=False)
                resolved.relative_to(quarantine_root)
                target_path = str(resolved)
            except (OSError, ValueError):
                base["matches"] = []
                base["error"] = "scope_path_not_in_quarantine_root"
                return base
    if target_path is None or not Path(target_path).is_file():
        base["matches"] = []
        base["error"] = "target_not_found"
        return base

    try:
        rules = yara.compile(filepath=str(candidate))
        results = rules.match(target_path)
    except Exception as exc:
        base["matches"] = []
        base["error"] = f"{type(exc).__name__}: {exc}"
        return base

    base["target_path"] = target_path
    base["matches"] = [
        {
            "rule": m.rule,
            "namespace": getattr(m, "namespace", None),
            "tags": list(getattr(m, "tags", []) or []),
            "meta": dict(getattr(m, "meta", {}) or {}),
            "strings_count": len(getattr(m, "strings", []) or []),
        }
        for m in results
    ]
    return base


def _propose_detection(kind: str, draft: Dict[str, Any], **_: Any) -> Dict[str, Any]:
    return {
        "tool": "propose_detection",
        "kind": kind,
        "draft_digest": _echo_hash(draft if isinstance(draft, dict) else {"raw": str(draft)}),
        "validator": {"precision": None, "recall": None, "f1": None},
        "note": "Phase A stub; detection_validator lands in Pillar 4 §4.",
    }


def _detonate_in_sandbox(specimen_id: str | int, profile_id: str, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "detonate_in_sandbox",
        "specimen_id": specimen_id,
        "profile_id": profile_id,
        "run_id": None,
        "status": "queued",
        "note": "Phase A stub; materialize_run_outputs rewrite lands in Pillar 2.",
    }


def _query_intel_feed(
    source: str,
    iocs: List[str],
    _context: Optional[Dict[str, Any]] = None,
    **_: Any,
) -> Dict[str, Any]:
    """Enrich CVE-style IOCs against the internal CVE/KEV/EPSS/exploit tables.

    `source` is recorded for provenance but not used to gate the query — the
    enrichment payload is built from whatever rows we have. Non-CVE IOCs
    (hashes, domains, IPs) are echoed back with a "no_local_enrichment"
    note so the agent can pivot to other tools.
    """

    iocs = list(iocs or [])
    base = {"tool": "query_intel_feed", "source": source, "iocs": iocs, "enrichment": []}
    session = _ctx_session(_context)
    if session is None:
        base["note"] = "No DB context supplied."
        return base

    from app.models.cve import CVE
    from app.models.sheshnaag import ExploitSignal
    from app.models.v2 import EPSSSnapshot, KEVEntry

    enrichment: List[Dict[str, Any]] = []
    for ioc in iocs:
        if not isinstance(ioc, str) or not ioc.upper().startswith("CVE-"):
            enrichment.append({"ioc": ioc, "note": "no_local_enrichment_for_non_cve"})
            continue
        cve_id_norm = ioc.upper()
        cve = session.query(CVE).filter(CVE.cve_id == cve_id_norm).first()
        kev = session.query(KEVEntry).filter(KEVEntry.cve_id == cve_id_norm).first()
        epss = (
            session.query(EPSSSnapshot)
            .filter(EPSSSnapshot.cve_id == cve_id_norm)
            .order_by(EPSSSnapshot.scored_at.desc())
            .first()
        )
        # ExploitSignal.cve_id is the integer PK FK (cves.id), not the string.
        signals = (
            session.query(ExploitSignal)
            .filter(ExploitSignal.cve_id == cve.id)
            .limit(10)
            .all()
            if cve is not None
            else []
        )
        if cve is None and kev is None and epss is None and not signals:
            enrichment.append({"ioc": ioc, "note": "cve_not_in_local_corpus"})
            continue
        enrichment.append({
            "ioc": ioc,
            "cve": {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": getattr(cve, "cvss_score", None),
                "published_date": cve.published_date.isoformat() if getattr(cve, "published_date", None) else None,
            } if cve else None,
            "kev": {
                "vendor_project": kev.vendor_project,
                "product": kev.product,
                "short_description": kev.short_description,
                "date_added": kev.date_added.isoformat() if getattr(kev, "date_added", None) else None,
            } if kev else None,
            "epss": {
                "score": epss.score,
                "percentile": epss.percentile,
                "scored_at": epss.scored_at.isoformat() if epss.scored_at else None,
            } if epss else None,
            "exploit_signals": [
                {"type": s.signal_type, "value": s.signal_value, "confidence": s.confidence}
                for s in signals
            ],
        })

    base["enrichment"] = enrichment
    base["count"] = len(enrichment)
    return base


def _export_external(bundle_id: str, target: str, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "export_external",
        "bundle_id": bundle_id,
        "target": target,
        "accepted": False,
        "reason": "Awaiting STIX exporter (Pillar 3 §3.2); capability gate: external_disclosure.",
    }


def _run_authorized_offensive(target: str, recipe_id: str, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "run_authorized_offensive",
        "target": target,
        "recipe_id": recipe_id,
        "run_id": None,
        "note": (
            "Phase A stub; requires a signed authorization artifact for the"
            " 'offensive_research' capability (two reviewers + expiry ≤ 7 days)."
        ),
    }


TOOL_REGISTRY: Dict[str, Tool] = {
    "fetch_specimen_triage": Tool(
        name="fetch_specimen_triage",
        description="Load static triage (hashes, size, imports, tags) for a specimen.",
        input_schema={
            "type": "object",
            "properties": {"specimen_id": {"type": "string"}},
            "required": ["specimen_id"],
        },
        capability=None,
        callable=_fetch_specimen_triage,
        tags=("read",),
        requires_context=True,
    ),
    "query_knowledge": Tool(
        name="query_knowledge",
        description="BM25 + pgvector hybrid search over the internal knowledge corpus.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "k": {"type": "integer", "default": 8, "minimum": 1, "maximum": 50},
            },
            "required": ["query"],
        },
        capability=None,
        callable=_query_knowledge,
        tags=("read", "rag"),
        requires_context=True,
    ),
    "pivot_ioc": Tool(
        name="pivot_ioc",
        description="Return the neighborhood of an IOC in the exposure graph.",
        input_schema={
            "type": "object",
            "properties": {"indicator_value": {"type": "string"}},
            "required": ["indicator_value"],
        },
        capability=None,
        callable=_pivot_ioc,
        tags=("read", "graph"),
        requires_context=True,
    ),
    "run_yara_scan": Tool(
        name="run_yara_scan",
        description="Scan quarantine with a named ruleset over a given scope.",
        input_schema={
            "type": "object",
            "properties": {
                "ruleset_id": {"type": "string"},
                "scope": {"type": "object"},
            },
            "required": ["ruleset_id"],
        },
        capability=None,
        callable=_run_yara_scan,
        tags=("read",),
        requires_context=True,
    ),
    "propose_detection": Tool(
        name="propose_detection",
        description="Validate a proposed Sigma/YARA/Snort/Falco rule against corpus.",
        input_schema={
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["sigma", "yara", "snort", "falco"]},
                "draft": {"type": "object"},
            },
            "required": ["kind", "draft"],
        },
        capability=None,
        callable=_propose_detection,
        tags=("write", "detection"),
    ),
    "detonate_in_sandbox": Tool(
        name="detonate_in_sandbox",
        description="Run the specimen in the specified sandbox profile.",
        input_schema={
            "type": "object",
            "properties": {
                "specimen_id": {"type": "string"},
                "profile_id": {"type": "string"},
            },
            "required": ["specimen_id", "profile_id"],
        },
        capability="dynamic_detonation",
        callable=_detonate_in_sandbox,
        tags=("write", "destructive"),
    ),
    "query_intel_feed": Tool(
        name="query_intel_feed",
        description="Enrich a list of IOCs against the named intel source.",
        input_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "iocs": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["source", "iocs"],
        },
        capability=None,
        callable=_query_intel_feed,
        tags=("read", "intel"),
        requires_context=True,
    ),
    "export_external": Tool(
        name="export_external",
        description="Emit a bundle externally (TAXII/STIX/MISP/PDF).",
        input_schema={
            "type": "object",
            "properties": {
                "bundle_id": {"type": "string"},
                "target": {"type": "string"},
            },
            "required": ["bundle_id", "target"],
        },
        capability="external_disclosure",
        callable=_export_external,
        tags=("write", "external"),
    ),
    "run_authorized_offensive": Tool(
        name="run_authorized_offensive",
        description="Execute an authorized offensive recipe against an in-lab target.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "recipe_id": {"type": "string"},
            },
            "required": ["target", "recipe_id"],
        },
        capability="offensive_research",
        callable=_run_authorized_offensive,
        tags=("write", "offensive"),
    ),
}


def get_tool(name: str) -> Optional[Tool]:
    return TOOL_REGISTRY.get(name)


def tool_schemas() -> list:
    """Return every tool's model-facing schema (for adapter `tools=` arg)."""
    return [t.describe() for t in TOOL_REGISTRY.values()]
