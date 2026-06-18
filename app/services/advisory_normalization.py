"""Canonical advisory normalization helpers for scoring and ingestion."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

_ECOSYSTEM_ALIASES = {
    "pip": "pypi",
    "python": "pypi",
    "npmjs": "npm",
    "rubygems.org": "rubygems",
    "golang": "go",
}


def normalize_ecosystem(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return _ECOSYSTEM_ALIASES.get(normalized, normalized)


def normalize_package_name(name: str | None, *, ecosystem: str | None = None) -> str:
    normalized = str(name or "").strip()
    eco = normalize_ecosystem(ecosystem)
    if eco in {"pypi", "npm", "rubygems"}:
        return normalized.lower()
    return normalized


def normalize_purl(value: str | None) -> str | None:
    raw = str(value or "").strip()
    return raw.lower() or None


def advisory_type_for_external_id(external_id: str | None, *, raw_type: str | None = None) -> str:
    if raw_type:
        return str(raw_type).strip().lower()
    value = str(external_id or "").strip().upper()
    if value.startswith("GHSA-"):
        return "ghsa"
    if value.startswith("OSV-"):
        return "osv"
    if value.startswith("CVE-"):
        return "cve"
    return "advisory"


def canonical_advisory_id(*, external_id: str | None, aliases: Iterable[str] = ()) -> str:
    choices = [str(external_id or "").strip()]
    choices.extend(str(alias or "").strip() for alias in aliases)
    cleaned = [choice for choice in choices if choice]
    if not cleaned:
        return "unknown"
    cleaned.sort(key=lambda item: (0 if item.upper().startswith("CVE-") else 1, len(item), item))
    return cleaned[0].upper() if cleaned[0].upper().startswith("GHSA-") else cleaned[0]


def dedupe_references(refs: Iterable[Any]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for ref in refs:
        if isinstance(ref, str):
            item = {"type": "WEB", "url": ref}
        elif isinstance(ref, dict):
            url = str(ref.get("url") or "").strip()
            if not url:
                continue
            item = {"type": str(ref.get("type") or "WEB"), "url": url}
            if ref.get("label"):
                item["label"] = ref.get("label")
        else:
            continue
        key = (str(item.get("type") or "").upper(), str(item.get("url") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def advisory_normalization_confidence(
    *,
    aliases: Iterable[str] = (),
    packages: Iterable[dict[str, Any]] = (),
    version_ranges: Iterable[dict[str, Any]] = (),
    references: Iterable[dict[str, Any]] = (),
) -> float:
    score = 0.2
    if any(str(alias).upper().startswith("CVE-") for alias in aliases):
        score += 0.2
    if list(packages):
        score += 0.2
    if list(version_ranges):
        score += 0.2
    if list(references):
        score += 0.1
    if len(list(packages)) > 1:
        score += 0.05
    if len(list(version_ranges)) > 1:
        score += 0.05
    return round(min(1.0, score), 3)


def parse_version_range_expression(expression: str | None) -> dict[str, Any]:
    raw = str(expression or "").strip()
    if not raw:
        return {
            "raw": "",
            "constraints": [],
            "version_start": None,
            "version_end": None,
            "fixed_version": None,
            "inclusive_start": True,
            "inclusive_end": False,
        }

    constraints: list[dict[str, Any]] = []
    version_start: str | None = None
    version_end: str | None = None
    fixed_version: str | None = None
    inclusive_start = True
    inclusive_end = False

    for segment in [part.strip() for part in raw.split(",") if part.strip()]:
        match = re.match(r"^(<=|>=|<|>|=)?\s*(.+)$", segment)
        if not match:
            continue
        operator = match.group(1) or "="
        version = match.group(2).strip()
        constraints.append({"operator": operator, "version": version})
        if operator in {">", ">="}:
            version_start = version
            inclusive_start = operator == ">="
        elif operator in {"<", "<="}:
            version_end = version
            inclusive_end = operator == "<="
        elif operator == "=":
            version_start = version
            version_end = version
            inclusive_start = True
            inclusive_end = True
    if version_end and not fixed_version and not inclusive_end:
        fixed_version = version_end
    return {
        "raw": raw,
        "constraints": constraints,
        "version_start": version_start,
        "version_end": version_end,
        "fixed_version": fixed_version,
        "inclusive_start": inclusive_start,
        "inclusive_end": inclusive_end,
    }


def build_canonical_package(package: dict[str, Any]) -> dict[str, Any]:
    ecosystem = normalize_ecosystem(package.get("ecosystem"))
    name = normalize_package_name(package.get("name"), ecosystem=ecosystem)
    return {
        "ecosystem": ecosystem,
        "name": name,
        "purl": normalize_purl(package.get("purl")),
    }


def summarize_advisory_records(records: Iterable[Any]) -> dict[str, Any]:
    advisories = list(records)
    packages: list[dict[str, Any]] = []
    aliases: set[str] = set()
    advisories_by_type: dict[str, int] = {}
    confidence_values: list[float] = []
    ids: list[str] = []

    for record in advisories:
        advisory_type = str(getattr(record, "advisory_type", None) or "advisory")
        advisories_by_type[advisory_type] = advisories_by_type.get(advisory_type, 0) + 1
        raw_aliases = getattr(record, "aliases", None) or []
        aliases.update(str(alias) for alias in raw_aliases if alias)
        confidence_values.append(float(getattr(record, "normalization_confidence", 0.5) or 0.5))
        if getattr(record, "external_id", None):
            ids.append(str(record.external_id))
        raw = getattr(record, "raw_data", None) or {}
        normalized_packages = raw.get("normalized_packages") if isinstance(raw, dict) else []
        if isinstance(normalized_packages, list):
            packages.extend(pkg for pkg in normalized_packages if isinstance(pkg, dict))

    canonical_packages: dict[tuple[str, str], dict[str, Any]] = {}
    for pkg in packages:
        canonical = build_canonical_package(pkg)
        key = (canonical["ecosystem"], canonical["name"])
        canonical_packages[key] = canonical

    source_agreement = (
        1.0 if len({pkg["name"] for pkg in canonical_packages.values()}) <= 1 else 0.6
    )
    return {
        "count": len(advisories),
        "external_ids": ids,
        "advisories_by_type": advisories_by_type,
        "aliases": sorted(aliases),
        "normalized_packages": list(canonical_packages.values()),
        "normalization_confidence": round(sum(confidence_values) / len(confidence_values), 3)
        if confidence_values
        else 0.5,
        "source_agreement": source_agreement,
        "conflicts": [] if source_agreement >= 1.0 else ["multiple_package_names_detected"],
    }
