"""Registry of callable tools exposed to models under capability-policy control.

Tools here are intentionally thin: the V4 agent loop asks the capability policy
for permission, then invokes `callable`. Deep logic (RAG retrieval, YARA,
detonation, intel feeds) lands in dedicated services during later V4 phases;
these stubs exist so Phase A can exercise the agent loop end-to-end with
realistic shapes.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    capability: Optional[str]
    callable: Callable[..., Dict[str, Any]]
    tags: tuple = field(default_factory=tuple)

    def describe(self) -> Dict[str, Any]:
        """Return the model-facing tool schema."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


# -- Stub implementations ------------------------------------------------------
#
# Each stub validates its input against the declared schema (best-effort),
# records provenance, and returns a grounded-looking response shape that later
# real implementations will continue to satisfy.


def _echo_hash(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(repr(sorted(payload.items())).encode("utf-8")).hexdigest()[:16]


def _fetch_specimen_triage(specimen_id: str | int, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "fetch_specimen_triage",
        "specimen_id": specimen_id,
        "triage": {
            "kind": "unknown",
            "size_bytes": 0,
            "sha256": None,
            "first_seen": None,
            "tags": [],
            "notes": "Phase A stub; real triage lands in Pillar 2.",
        },
        "fetched_at": time.time(),
    }


def _query_knowledge(query: str, k: int = 8, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "query_knowledge",
        "query": query,
        "k": int(k),
        "hits": [],
        "note": "Phase A stub; pgvector RAG lands in Pillar 1 §1.3.",
    }


def _pivot_ioc(indicator_value: str, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "pivot_ioc",
        "indicator_value": indicator_value,
        "neighbors": [],
        "note": "Phase A stub; graph pivot lands in Pillar 3 §3.3.",
    }


def _run_yara_scan(ruleset_id: str, scope: Dict[str, Any], **_: Any) -> Dict[str, Any]:
    return {
        "tool": "run_yara_scan",
        "ruleset_id": ruleset_id,
        "scope": scope,
        "matches": [],
        "note": "Phase A stub; live YARA scanner in Pillar 4.",
    }


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


def _query_intel_feed(source: str, iocs: list, **_: Any) -> Dict[str, Any]:
    return {
        "tool": "query_intel_feed",
        "source": source,
        "iocs": list(iocs or []),
        "enrichment": [],
        "note": "Phase A stub; connectors land in Pillar 3 §3.1.",
    }


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
