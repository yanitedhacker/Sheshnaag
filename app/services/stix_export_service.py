"""STIX 2.1 export of an analysis case.

Builds a STIX 2.1 ``Bundle`` from:

* the AnalysisCase (Identity + Report)
* its IndicatorArtifacts (Indicator SDOs with appropriate patterns)
* its BehaviorFindings (ObservedData / Sighting depending on payload)
* the linked Specimens (Malware SDOs)

Pure read path. The bundle is serialised as JSON; callers can persist it
to MinIO via the existing object_store, attach it to a DisclosureBundle,
or stream it back over HTTP.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import stix2
from sqlalchemy.orm import Session

from app.models.malware_lab import (
    AnalysisCase,
    BehaviorFinding,
    IndicatorArtifact,
    Specimen,
)
from app.models.v2 import Tenant

logger = logging.getLogger(__name__)

_PATTERN_BUILDERS = {
    "domain": lambda v: f"[domain-name:value = '{_q(v)}']",
    "ipv4": lambda v: f"[ipv4-addr:value = '{_q(v)}']",
    "ipv6": lambda v: f"[ipv6-addr:value = '{_q(v)}']",
    "url": lambda v: f"[url:value = '{_q(v)}']",
    "email": lambda v: f"[email-addr:value = '{_q(v)}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{_q(v)}']",
    "md5": lambda v: f"[file:hashes.MD5 = '{_q(v)}']",
    "sha1": lambda v: f"[file:hashes.'SHA-1' = '{_q(v)}']",
}


def _q(value: str) -> str:
    """Escape single quotes for STIX pattern literals."""
    return value.replace("'", r"\'")


class StixExportService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def export_case(self, tenant: Tenant, *, case_id: int) -> Dict[str, Any]:
        case = (
            self.session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == case_id)
            .first()
        )
        if case is None:
            raise ValueError("analysis_case_not_found")

        indicators = (
            self.session.query(IndicatorArtifact)
            .filter(
                IndicatorArtifact.tenant_id == tenant.id,
                IndicatorArtifact.analysis_case_id == case.id,
            )
            .all()
        )
        findings = (
            self.session.query(BehaviorFinding)
            .filter(
                BehaviorFinding.tenant_id == tenant.id,
                BehaviorFinding.analysis_case_id == case.id,
            )
            .all()
        )
        specimen_ids: List[int] = list(case.specimen_ids or [])
        specimens: List[Specimen] = (
            self.session.query(Specimen)
            .filter(Specimen.tenant_id == tenant.id, Specimen.id.in_(specimen_ids))
            .all()
            if specimen_ids
            else []
        )

        identity = stix2.Identity(
            name=tenant.name or tenant.slug,
            identity_class="organization",
            description=f"Sheshnaag tenant {tenant.slug}",
        )

        objects: List[Any] = [identity]
        object_refs: List[str] = []

        for ind in indicators:
            pattern_builder = _PATTERN_BUILDERS.get((ind.indicator_kind or "").lower())
            if pattern_builder is None:
                # Fallback: treat as opaque file:name pattern so the indicator
                # still appears in the bundle for context — STIX doesn't
                # require us to model every IOC kind exhaustively.
                pattern = f"[file:name = '{_q(ind.value)}']"
            else:
                pattern = pattern_builder(ind.value)
            sdo = stix2.Indicator(
                pattern=pattern,
                pattern_type="stix",
                created_by_ref=identity.id,
                indicator_types=["malicious-activity"],
                name=f"{ind.indicator_kind}:{ind.value}",
                confidence=int(round((ind.confidence or 0) * 100)),
                description=(ind.source or "Sheshnaag analysis"),
            )
            objects.append(sdo)
            object_refs.append(sdo.id)

        for spec in specimens:
            sdo = stix2.Malware(
                name=spec.name,
                is_family=False,
                created_by_ref=identity.id,
                malware_types=["unknown"],
                description=(spec.summary or f"Specimen kind={spec.specimen_kind}"),
            )
            objects.append(sdo)
            object_refs.append(sdo.id)

        for f in findings:
            note = stix2.Note(
                content=f.title,
                abstract=f"severity={f.severity} confidence={f.confidence}",
                authors=[tenant.slug],
                object_refs=[identity.id],  # bare-minimum required ref
                created_by_ref=identity.id,
            )
            objects.append(note)
            object_refs.append(note.id)

        # Tie everything together with a Report SDO so consumers can grasp
        # the case scope at a glance.
        report = stix2.Report(
            name=case.title,
            published=(case.created_at or None),
            report_types=["threat-report"],
            created_by_ref=identity.id,
            object_refs=object_refs or [identity.id],
            description=case.summary or f"Analysis case {case.id}",
        )
        objects.append(report)

        bundle = stix2.Bundle(objects=objects, allow_custom=False)
        # `bundle.serialize()` returns JSON text; round-trip to dict so the
        # API can return a real JSON object rather than a string.
        import json
        return json.loads(bundle.serialize())
