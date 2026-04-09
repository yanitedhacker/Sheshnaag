"""Candidate scoring and explainability helpers for Sheshnaag."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


CANDIDATE_SCORING_WEIGHTS: Dict[str, float] = {
    "risk_score": 0.14,
    "epss": 0.09,
    "kev": 0.09,
    "package_match_confidence": 0.08,
    "affected_version_confidence": 0.08,
    "sbom_vex_applicability": 0.08,
    "attack_surface": 0.06,
    "observability": 0.06,
    "linux_reproducibility": 0.06,
    "patch_availability": 0.05,
    "exploit_maturity": 0.05,
    "advisory_normalization_confidence": 0.04,
    "source_agreement": 0.03,
    "vendor_context_quality": 0.03,
    "source_freshness": 0.03,
    "evidence_readiness": 0.03,
}


@dataclass
class ScoringFactor:
    key: str
    raw_value: float
    weight: float
    weighted_value: float
    reason: str


@dataclass
class CandidateScoringContext:
    risk_val: float
    epss_val: float
    kev: bool
    package_match_confidence: float
    affected_version_confidence: float
    sbom_vex_applicability: float
    attack_surface: float
    observability: float
    linux_reproducibility: float
    patch_availability_factor: float
    exploit_maturity: float
    advisory_normalization_confidence: float
    source_agreement: float
    vendor_context_quality: float
    source_freshness: float
    evidence_readiness: float
    applicability: Dict[str, Any]
    advisory_summary: Dict[str, Any]
    citations: List[Dict[str, Any]]


def compute_candidate_explainability(context: CandidateScoringContext) -> Dict[str, Any]:
    w = CANDIDATE_SCORING_WEIGHTS
    raw = {
        "risk_score": (context.risk_val, "Overall risk composite from prior scoring"),
        "epss": (context.epss_val, f"EPSS probability {context.epss_val:.3f}" if context.epss_val else "No EPSS data available"),
        "kev": (1.0 if context.kev else 0.0, "In CISA KEV catalog" if context.kev else "Not in KEV catalog"),
        "package_match_confidence": (
            context.package_match_confidence,
            f"Asset/SBOM alignment confidence {context.package_match_confidence:.2f}",
        ),
        "affected_version_confidence": (
            context.affected_version_confidence,
            f"Affected-vs-fixed version confidence {context.affected_version_confidence:.2f}",
        ),
        "sbom_vex_applicability": (
            context.sbom_vex_applicability,
            "Combined SBOM and VEX applicability strength",
        ),
        "attack_surface": (context.attack_surface, "Network-reachable and remotely triggerable issues score higher"),
        "observability": (context.observability, "Telemetry depth expected for this candidate"),
        "linux_reproducibility": (context.linux_reproducibility, "Confidence the issue is reproducible in the lab"),
        "patch_availability": (
            context.patch_availability_factor,
            "Patch/fix availability influences urgency and operator value",
        ),
        "exploit_maturity": (context.exploit_maturity, "Composite of KEV, EPSS, and exploit hints"),
        "advisory_normalization_confidence": (
            context.advisory_normalization_confidence,
            "Confidence in merged OSV/GHSA/vendor/package normalization",
        ),
        "source_agreement": (
            context.source_agreement,
            "Agreement between upstream advisory sources and package matches",
        ),
        "vendor_context_quality": (
            context.vendor_context_quality,
            "Vendor advisories and patch-note context improve operator usefulness",
        ),
        "source_freshness": (context.source_freshness, "Upstream feeds are fresh enough for candidate materialization"),
        "evidence_readiness": (context.evidence_readiness, "Current provider and collector path readiness"),
    }
    factors = [
        ScoringFactor(key=key, raw_value=value, weight=w[key], weighted_value=value * w[key], reason=reason)
        for key, (value, reason) in raw.items()
    ]
    weighted_total = sum(item.weighted_value for item in factors)
    score = round(weighted_total * 100.0, 2)
    citation_groups: Dict[str, List[Dict[str, Any]]] = {}
    for citation in context.citations:
        group = str(citation.get("type") or "other").split("_", 1)[0]
        citation_groups.setdefault(group, []).append(citation)

    return {
        "score": score,
        "factors": {
            factor.key: round(factor.raw_value, 3) if factor.key != "kev" else bool(context.kev)
            for factor in factors
        },
        "weights": dict(CANDIDATE_SCORING_WEIGHTS),
        "factor_details": [
            {
                "key": factor.key,
                "raw": round(factor.raw_value, 3),
                "weight": factor.weight,
                "weighted": round(factor.weighted_value, 4),
                "reason": factor.reason,
            }
            for factor in factors
        ],
        "asset_match_count": int(context.applicability.get("asset_match_count") or 0) + int(context.applicability.get("sbom_match_count") or 0),
        "patch_available": bool(context.applicability.get("patch_available")),
        "observability_score": round(context.observability, 3),
        "linux_reproducibility_confidence": round(context.linux_reproducibility, 3),
        "environment_applicability": context.applicability,
        "normalized_advisories": context.advisory_summary,
        "applicability_summary": {
            "package_match_confidence": round(context.package_match_confidence, 3),
            "affected_version_confidence": round(context.affected_version_confidence, 3),
            "sbom_vex_applicability": round(context.sbom_vex_applicability, 3),
        },
        "citation_groups": citation_groups,
        "citations": context.citations,
    }
