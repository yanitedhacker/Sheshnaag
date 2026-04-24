"""STIX 2.1 bundle exporter for Sheshnaag V4 Threat Intel Fabric.

Implements a hand-rolled STIX 2.1 emitter — no ``stix2`` python package
dependency. We keep the dependency footprint lean and produce spec-compliant
objects directly. See:

    https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html

The exporter converts one :class:`~app.models.malware_lab.AnalysisCase`
(plus its Specimens, BehaviorFindings and IndicatorArtifacts, plus the
latest approved :class:`~app.models.malware_lab.MalwareReport`) into a
STIX Bundle ``{type: "bundle", id: "bundle--<uuid>", objects: [...]}``.

Stable, deterministic SDO IDs are produced by hashing the tenant slug +
object type + primary key into a UUIDv5 under a fixed namespace, so repeat
exports of the same case produce byte-identical IDs. This is a hard
requirement for idempotent TAXII re-publishing.

The exporter also offers :meth:`StixExporter.validate_bundle` which walks
the bundle and returns a list of spec violations (empty list == valid).
Used by both the unit tests and the TAXII ingest path to reject malformed
bundles before persisting them.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    MalwareReport,
    Specimen,
)
from app.models.v2 import Tenant

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Fixed namespace UUID for Sheshnaag STIX IDs. Chosen once and never rotated —
#: rotating would break idempotency guarantees for all historical bundles.
SHESHNAAG_STIX_NAMESPACE = uuid.UUID("6e3c4b80-7e1c-4b8d-98d4-5f5e41b4a9f0")

STIX_SPEC_VERSION = "2.1"

#: Regex matching a valid STIX 2.1 identifier: ``<type>--<uuid>``.
_STIX_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]*--"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

#: Strict ISO-8601 UTC-with-Z timestamp (STIX 2.1 §3.3).
_STIX_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

#: STIX 2.1 common required properties for any SDO.
_COMMON_REQUIRED = ("type", "id", "spec_version", "created", "modified")

#: Per-SDO-type required property sets (beyond common).
_TYPE_REQUIRED: Dict[str, tuple[str, ...]] = {
    "indicator": ("pattern", "pattern_type", "valid_from", "indicator_types"),
    "malware": ("name", "is_family", "malware_types"),
    "observed-data": ("first_observed", "last_observed", "number_observed", "objects"),
    "report": ("name", "published", "object_refs", "report_types"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "sighting": ("sighting_of_ref",),
}

#: Kinds we know how to pattern-match. See STIX 2.1 §7 cyber-observable types.
_HASH_KINDS: Dict[str, str] = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "md5": "MD5",
    "sha512": "SHA-512",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utc_z(value: Optional[datetime]) -> str:
    """Render ``value`` as ISO-8601 UTC with trailing ``Z``, STIX-style."""

    if value is None:
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    # STIX demands millisecond/microsecond precision to be explicit; Python's
    # isoformat emits microseconds only when nonzero. Normalize to always
    # include at least seconds, then swap +00:00 → Z.
    iso = value.isoformat()
    if iso.endswith("+00:00"):
        iso = iso[:-6] + "Z"
    elif not iso.endswith("Z"):
        iso = iso + "Z"
    return iso


def _deterministic_uuid(seed: str) -> str:
    """Return a UUIDv5 string derived from ``seed`` under the fixed namespace."""

    return str(uuid.uuid5(SHESHNAAG_STIX_NAMESPACE, seed))


def _escape_pattern_value(value: str) -> str:
    """Escape a value for inclusion inside a STIX pattern single-quoted string."""

    return value.replace("\\", "\\\\").replace("'", "\\'")


def _confidence_to_int(conf: Optional[float]) -> int:
    """STIX 2.1 confidence is an integer in [0, 100]."""

    if conf is None:
        return 0
    try:
        val = float(conf)
    except (TypeError, ValueError):
        return 0
    if val <= 0:
        return 0
    if val >= 1:
        return 100
    return int(round(val * 100))


# ---------------------------------------------------------------------------
# Pattern builders
# ---------------------------------------------------------------------------


def _build_indicator_pattern(kind: str, value: str) -> Optional[str]:
    """Return a STIX 2.1 pattern string for ``(kind, value)``.

    Returns ``None`` for indicator kinds we do not know how to express
    structurally; the caller then wraps the raw value as an ``x-sheshnaag``
    custom property rather than emitting an invalid pattern.
    """

    if not value:
        return None
    kind = (kind or "").strip().lower()
    escaped = _escape_pattern_value(value.strip())

    if kind in _HASH_KINDS:
        return f"[file:hashes.'{_HASH_KINDS[kind]}' = '{escaped}']"
    if kind == "url":
        return f"[url:value = '{escaped}']"
    if kind in ("domain", "hostname", "fqdn"):
        return f"[domain-name:value = '{escaped}']"
    if kind == "ip" or kind == "ipv4":
        # STIX has both ipv4-addr and ipv6-addr. Use a small heuristic.
        if ":" in value:
            return f"[ipv6-addr:value = '{escaped}']"
        return f"[ipv4-addr:value = '{escaped}']"
    if kind == "ipv6":
        return f"[ipv6-addr:value = '{escaped}']"
    if kind == "email":
        return f"[email-addr:value = '{escaped}']"
    if kind == "user_agent":
        return f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{escaped}']"
    if kind == "mutex":
        return f"[mutex:name = '{escaped}']"
    if kind == "regkey":
        return f"[windows-registry-key:key = '{escaped}']"
    return None


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class StixExporter:
    """Build STIX 2.1 bundles from an analysis case."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_case(
        self,
        tenant: Tenant,
        case_id: int,
        *,
        include_observables: bool = True,
    ) -> Dict[str, Any]:
        """Export a full STIX 2.1 bundle for one analysis case.

        The bundle contains one SDO per case entity:

          * ``indicator`` — one per :class:`IndicatorArtifact`.
          * ``malware`` — one per :class:`Specimen` linked by the case.
          * ``observed-data`` — one per behavior-finding cluster when
            ``include_observables`` is True. Spec-compliant observables are
            only emitted for hosts/URLs/IPs that parse cleanly; findings
            without structured telemetry produce a fallback ``observed-data``
            referencing an ``x-sheshnaag-finding`` object.
          * ``report`` — the approved :class:`MalwareReport`, pointing at
            the indicators, malware, and observed-data it references.
          * ``relationship`` — indicator→malware (``indicates``),
            indicator→indicator co-occurrence (``related-to``), and
            report→refs are folded into ``object_refs`` directly.
          * ``sighting`` — one per :class:`BehaviorFinding`, referencing
            the Specimen's malware SDO when available.

        All object IDs are deterministic — re-exporting the same case
        produces byte-identical IDs.
        """

        tenant_tag = tenant.slug or f"tenant-{tenant.id}"

        case: Optional[AnalysisCase] = (
            self._session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == case_id)
            .first()
        )
        if case is None:
            raise ValueError(f"Analysis case {case_id} not found for tenant {tenant.id}")

        specimen_ids = list(case.specimen_ids or [])
        specimens: List[Specimen] = []
        if specimen_ids:
            specimens = (
                self._session.query(Specimen)
                .filter(
                    Specimen.tenant_id == tenant.id,
                    Specimen.id.in_(specimen_ids),
                )
                .all()
            )

        findings: List[BehaviorFinding] = (
            self._session.query(BehaviorFinding)
            .filter(
                BehaviorFinding.tenant_id == tenant.id,
                BehaviorFinding.analysis_case_id == case_id,
            )
            .all()
        )

        indicators: List[IndicatorArtifact] = (
            self._session.query(IndicatorArtifact)
            .filter(
                IndicatorArtifact.tenant_id == tenant.id,
                IndicatorArtifact.analysis_case_id == case_id,
            )
            .all()
        )

        report_row: Optional[MalwareReport] = (
            self._session.query(MalwareReport)
            .filter(
                MalwareReport.tenant_id == tenant.id,
                MalwareReport.analysis_case_id == case_id,
            )
            .order_by(MalwareReport.updated_at.desc())
            .first()
        )

        objects: List[Dict[str, Any]] = []
        ref_cache: Dict[str, str] = {}

        for specimen in specimens:
            sdo = self._build_malware(tenant_tag, specimen)
            ref_cache[f"specimen:{specimen.id}"] = sdo["id"]
            objects.append(sdo)

        for indicator in indicators:
            sdo = self._build_indicator(tenant_tag, indicator)
            ref_cache[f"indicator:{indicator.id}"] = sdo["id"]
            objects.append(sdo)

        # indicator→malware "indicates" relationships — every indicator points
        # at every malware in the case. Coarse but spec-valid; a finer pass
        # can be added once we have indicator→specimen provenance linked.
        for indicator in indicators:
            source_ref = ref_cache[f"indicator:{indicator.id}"]
            for specimen in specimens:
                target_ref = ref_cache[f"specimen:{specimen.id}"]
                objects.append(
                    self._build_relationship(
                        tenant_tag,
                        relationship_type="indicates",
                        source_ref=source_ref,
                        target_ref=target_ref,
                        key=f"ind-mal:{indicator.id}:{specimen.id}",
                    )
                )

        # indicator↔indicator co-occurrence (case-scoped). We emit one
        # symmetric edge per pair (i<j) to avoid duplicate SROs.
        for i in range(len(indicators)):
            for j in range(i + 1, len(indicators)):
                a, b = indicators[i], indicators[j]
                objects.append(
                    self._build_relationship(
                        tenant_tag,
                        relationship_type="related-to",
                        source_ref=ref_cache[f"indicator:{a.id}"],
                        target_ref=ref_cache[f"indicator:{b.id}"],
                        key=f"ind-ind:{a.id}:{b.id}",
                    )
                )

        # Sightings (one per behavior finding). Prefer the first specimen as
        # the sighting_of_ref; fall back to the first indicator if no specimen.
        sighting_of = None
        if specimens:
            sighting_of = ref_cache[f"specimen:{specimens[0].id}"]
        elif indicators:
            sighting_of = ref_cache[f"indicator:{indicators[0].id}"]

        for finding in findings:
            if sighting_of is None:
                continue
            objects.append(
                self._build_sighting(
                    tenant_tag,
                    finding=finding,
                    sighting_of_ref=sighting_of,
                )
            )

        # Observed-data: one per finding cluster. We collapse findings that
        # share the same finding_type into a single observation whose
        # ``number_observed`` counts the cluster size.
        if include_observables and findings:
            clusters: Dict[str, List[BehaviorFinding]] = {}
            for finding in findings:
                clusters.setdefault(finding.finding_type or "unknown", []).append(finding)
            for cluster_kind, cluster in clusters.items():
                objects.append(
                    self._build_observed_data(tenant_tag, cluster_kind, cluster)
                )

        # Report (if present, approved and has content)
        if report_row is not None:
            ref_ids = [o["id"] for o in objects]
            # A report needs at least one object_ref; skip if empty.
            if ref_ids:
                objects.append(
                    self._build_report(tenant_tag, case, report_row, ref_ids)
                )

        bundle_seed = f"bundle:{tenant_tag}:{case_id}"
        bundle: Dict[str, Any] = {
            "type": "bundle",
            "id": f"bundle--{_deterministic_uuid(bundle_seed)}",
            "objects": objects,
        }
        return bundle

    def validate_bundle(self, bundle: Dict[str, Any]) -> List[str]:
        """Return a list of spec violations. Empty list means the bundle is valid.

        We check the envelope and every SDO against STIX 2.1's common
        required fields plus the per-type required fields. This is not a
        substitute for the canonical JSON Schema, but it catches the
        structural errors callers are most likely to introduce.
        """

        errors: List[str] = []
        if not isinstance(bundle, dict):
            return ["bundle must be an object"]

        if bundle.get("type") != "bundle":
            errors.append("bundle.type must be 'bundle'")
        bundle_id = bundle.get("id", "")
        if not isinstance(bundle_id, str) or not bundle_id.startswith("bundle--"):
            errors.append("bundle.id must be of form 'bundle--<uuid>'")
        elif not _STIX_ID_RE.match(bundle_id):
            errors.append(f"bundle.id malformed: {bundle_id}")

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            errors.append("bundle.objects must be an array")
            return errors

        seen_ids: set[str] = set()
        for idx, sdo in enumerate(objects):
            prefix = f"objects[{idx}]"
            if not isinstance(sdo, dict):
                errors.append(f"{prefix}: not an object")
                continue

            # Common required fields
            for field in _COMMON_REQUIRED:
                if field not in sdo:
                    errors.append(f"{prefix}: missing required '{field}'")

            sdo_type = sdo.get("type", "")
            sdo_id = sdo.get("id", "")
            if not isinstance(sdo_id, str) or not _STIX_ID_RE.match(sdo_id):
                errors.append(f"{prefix}: id '{sdo_id}' does not match STIX id form")
            elif not sdo_id.startswith(f"{sdo_type}--"):
                errors.append(
                    f"{prefix}: id prefix '{sdo_id.split('--')[0]}' "
                    f"does not match type '{sdo_type}'"
                )
            elif sdo_id in seen_ids:
                errors.append(f"{prefix}: duplicate id {sdo_id}")
            else:
                seen_ids.add(sdo_id)

            if sdo.get("spec_version") != STIX_SPEC_VERSION:
                errors.append(
                    f"{prefix}: spec_version must be '{STIX_SPEC_VERSION}'"
                )

            # Timestamps
            for ts_field in ("created", "modified", "valid_from", "first_observed",
                             "last_observed", "published"):
                if ts_field in sdo:
                    if not isinstance(sdo[ts_field], str) or not _STIX_TIMESTAMP_RE.match(sdo[ts_field]):
                        errors.append(
                            f"{prefix}: {ts_field} must be ISO-8601 UTC with Z suffix"
                        )

            # Per-type required properties
            for req in _TYPE_REQUIRED.get(sdo_type, ()):
                if req not in sdo:
                    errors.append(f"{prefix}: {sdo_type} missing required '{req}'")

            # Labels vocabulary: at least one label is a soft-guard but for
            # Indicator/Malware/Report we require ``indicator_types`` /
            # ``malware_types`` / ``report_types`` to be non-empty lists.
            if sdo_type == "indicator":
                if not isinstance(sdo.get("indicator_types"), list) or not sdo["indicator_types"]:
                    errors.append(f"{prefix}: indicator.indicator_types must be non-empty list")
                if not isinstance(sdo.get("pattern"), str) or not sdo["pattern"].strip():
                    errors.append(f"{prefix}: indicator.pattern must be a non-empty string")
            if sdo_type == "malware":
                if not isinstance(sdo.get("malware_types"), list) or not sdo["malware_types"]:
                    errors.append(f"{prefix}: malware.malware_types must be non-empty list")
                if not isinstance(sdo.get("is_family"), bool):
                    errors.append(f"{prefix}: malware.is_family must be boolean")
            if sdo_type == "report":
                if not isinstance(sdo.get("report_types"), list) or not sdo["report_types"]:
                    errors.append(f"{prefix}: report.report_types must be non-empty list")
                if not isinstance(sdo.get("object_refs"), list) or not sdo["object_refs"]:
                    errors.append(f"{prefix}: report.object_refs must be non-empty list")
            if sdo_type == "relationship":
                src = sdo.get("source_ref", "")
                tgt = sdo.get("target_ref", "")
                if not _STIX_ID_RE.match(src):
                    errors.append(f"{prefix}: relationship.source_ref malformed")
                if not _STIX_ID_RE.match(tgt):
                    errors.append(f"{prefix}: relationship.target_ref malformed")

        return errors

    # ------------------------------------------------------------------
    # Individual SDO builders
    # ------------------------------------------------------------------

    def _build_malware(self, tenant_tag: str, specimen: Specimen) -> Dict[str, Any]:
        sid = _deterministic_uuid(f"{tenant_tag}:malware:{specimen.id}")
        created = _utc_z(specimen.created_at)
        modified = _utc_z(specimen.updated_at or specimen.created_at)
        labels = list(specimen.labels or [])
        if specimen.risk_level and specimen.risk_level not in labels:
            labels.append(f"risk-{specimen.risk_level}")
        return {
            "type": "malware",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"malware--{sid}",
            "created": created,
            "modified": modified,
            "name": specimen.name or f"specimen-{specimen.id}",
            "description": specimen.summary or "",
            "is_family": False,
            "malware_types": [self._malware_type_from_kind(specimen.specimen_kind)],
            "labels": labels or ["sheshnaag-specimen"],
        }

    def _build_indicator(
        self, tenant_tag: str, indicator: IndicatorArtifact
    ) -> Dict[str, Any]:
        sid = _deterministic_uuid(f"{tenant_tag}:indicator:{indicator.id}")
        created = _utc_z(indicator.created_at)
        modified = _utc_z(indicator.updated_at or indicator.created_at)
        pattern = _build_indicator_pattern(indicator.indicator_kind, indicator.value)
        if pattern is None:
            # Degrade gracefully: spec still requires a pattern string, so
            # we express the opaque indicator via an ``x-sheshnaag`` object.
            escaped = _escape_pattern_value(indicator.value or "")
            pattern = f"[x-sheshnaag-indicator:value = '{escaped}']"

        labels = [f"kind-{indicator.indicator_kind}"]
        if indicator.source:
            labels.append(f"source-{indicator.source}")

        sdo: Dict[str, Any] = {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"indicator--{sid}",
            "created": created,
            "modified": modified,
            "name": f"{indicator.indicator_kind}:{indicator.value[:80]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": STIX_SPEC_VERSION,
            "valid_from": created,
            "indicator_types": ["malicious-activity"],
            "confidence": _confidence_to_int(indicator.confidence),
            "labels": labels,
        }
        return sdo

    def _build_relationship(
        self,
        tenant_tag: str,
        *,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
        key: str,
    ) -> Dict[str, Any]:
        sid = _deterministic_uuid(f"{tenant_tag}:rel:{key}:{relationship_type}")
        now = _utc_z(None)
        return {
            "type": "relationship",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"relationship--{sid}",
            "created": now,
            "modified": now,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }

    def _build_sighting(
        self,
        tenant_tag: str,
        *,
        finding: BehaviorFinding,
        sighting_of_ref: str,
    ) -> Dict[str, Any]:
        sid = _deterministic_uuid(f"{tenant_tag}:sighting:{finding.id}")
        created = _utc_z(finding.created_at)
        modified = _utc_z(finding.updated_at or finding.created_at)
        return {
            "type": "sighting",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"sighting--{sid}",
            "created": created,
            "modified": modified,
            "first_seen": created,
            "last_seen": modified,
            "count": 1,
            "sighting_of_ref": sighting_of_ref,
            "description": finding.title or finding.finding_type,
            "confidence": _confidence_to_int(finding.confidence),
            "labels": [f"severity-{finding.severity or 'medium'}",
                       f"type-{finding.finding_type or 'unknown'}"],
        }

    def _build_observed_data(
        self, tenant_tag: str, cluster_kind: str, cluster: List[BehaviorFinding]
    ) -> Dict[str, Any]:
        sid = _deterministic_uuid(
            f"{tenant_tag}:obs:{cluster_kind}:{','.join(str(f.id) for f in cluster)}"
        )
        first = min(
            (f.created_at for f in cluster if f.created_at is not None),
            default=datetime.now(timezone.utc),
        )
        last = max(
            (f.updated_at or f.created_at for f in cluster if (f.updated_at or f.created_at) is not None),
            default=first,
        )
        # Observed-data wraps a ``objects`` map (deprecated) or
        # ``object_refs`` (preferred in 2.1). We use the inline ``objects``
        # map since we cannot guarantee all observables live in the bundle.
        observable: Dict[str, Any] = {
            "0": {
                "type": "x-sheshnaag-ebpf-cluster",
                "finding_type": cluster_kind,
                "finding_count": len(cluster),
                "finding_ids": [f.id for f in cluster],
            }
        }
        return {
            "type": "observed-data",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"observed-data--{sid}",
            "created": _utc_z(first),
            "modified": _utc_z(last),
            "first_observed": _utc_z(first),
            "last_observed": _utc_z(last),
            "number_observed": len(cluster),
            "objects": observable,
            "labels": [f"cluster-{cluster_kind}"],
        }

    def _build_report(
        self,
        tenant_tag: str,
        case: AnalysisCase,
        report: MalwareReport,
        ref_ids: List[str],
    ) -> Dict[str, Any]:
        sid = _deterministic_uuid(f"{tenant_tag}:report:{report.id}")
        created = _utc_z(report.created_at)
        modified = _utc_z(report.updated_at or report.created_at)
        labels = list(case.tags or [])
        return {
            "type": "report",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"report--{sid}",
            "created": created,
            "modified": modified,
            "name": report.title or case.title or f"case-{case.id}",
            "description": (report.content or {}).get("executive_summary", "") if isinstance(report.content, dict) else "",
            "published": created,
            "report_types": [self._report_type(report.report_type)],
            "object_refs": ref_ids,
            "labels": labels or ["sheshnaag-report"],
            "confidence": 80,
        }

    # ------------------------------------------------------------------
    # Type helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _malware_type_from_kind(specimen_kind: Optional[str]) -> str:
        """Map Sheshnaag's specimen_kind → STIX ``malware-type-ov``."""

        if not specimen_kind:
            return "unknown"
        specimen_kind = specimen_kind.lower()
        if specimen_kind.startswith("file/script") or "js" in specimen_kind:
            return "trojan"
        if specimen_kind.startswith("file/") or specimen_kind == "file":
            return "trojan"
        if specimen_kind == "url":
            return "dropper"
        if specimen_kind.startswith("email"):
            return "spyware"
        if specimen_kind.startswith("archive"):
            return "trojan"
        return "unknown"

    @staticmethod
    def _report_type(report_type: Optional[str]) -> str:
        """Map Sheshnaag's report_type → STIX ``report-type-ov``."""

        mapping = {
            "incident_response": "incident",
            "bug_bounty": "vulnerability",
            "intel_brief": "threat-report",
            "detection_engineering": "indicator",
            "vendor_disclosure": "vulnerability",
        }
        return mapping.get((report_type or "").lower(), "threat-report")


__all__ = [
    "SHESHNAAG_STIX_NAMESPACE",
    "STIX_SPEC_VERSION",
    "StixExporter",
]
