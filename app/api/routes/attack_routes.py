"""V4 ATT&CK coverage APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.tenancy import resolve_tenant
from app.models.malware_lab import BehaviorFinding
from app.services.attack_mapper import TECHNIQUE_TACTICS

router = APIRouter(prefix="/api/v4/attack", tags=["Sheshnaag V4 ATT&CK"])


def _parse_since(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="since_must_be_iso_datetime") from exc


def _techniques(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("attack_techniques") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, str):
            out.append({"technique_id": item, "confidence": 0.5, "tactic": TECHNIQUE_TACTICS.get(item, "Unknown")})
        elif isinstance(item, dict) and item.get("technique_id"):
            technique_id = str(item["technique_id"])
            out.append(
                {
                    **item,
                    "technique_id": technique_id,
                    "confidence": float(item.get("confidence") or 0.5),
                    "tactic": str(item.get("tactic") or TECHNIQUE_TACTICS.get(technique_id, "Unknown")),
                }
            )
    return out


def _finding_payload(row: BehaviorFinding) -> dict[str, Any]:
    return {
        "id": row.id,
        "analysis_case_id": row.analysis_case_id,
        "run_id": row.run_id,
        "finding_type": row.finding_type,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "status": row.status,
        "payload": row.payload or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/coverage")
def attack_coverage(
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    since: Optional[str] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    query = session.query(BehaviorFinding).filter(BehaviorFinding.tenant_id == tenant.id)
    since_dt = _parse_since(since)
    if since_dt is not None:
        query = query.filter(BehaviorFinding.created_at >= since_dt)

    tactics: dict[str, dict[str, Any]] = {}
    for finding in query.all():
        for technique in _techniques(finding.payload or {}):
            tactic = str(technique.get("tactic") or "Unknown")
            technique_id = str(technique["technique_id"])
            tactic_bucket = tactics.setdefault(tactic, {"techniques": {}})
            bucket = tactic_bucket["techniques"].setdefault(
                technique_id,
                {"count": 0, "confidence_total": 0.0, "confidence_avg": 0.0, "finding_ids": []},
            )
            bucket["count"] += 1
            bucket["confidence_total"] += float(technique.get("confidence") or 0)
            bucket["confidence_avg"] = bucket["confidence_total"] / bucket["count"]
            bucket["finding_ids"].append(finding.id)

    for tactic in tactics.values():
        for bucket in tactic["techniques"].values():
            bucket.pop("confidence_total", None)

    return {"tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name}, "tactics": tactics}


@router.get("/technique/{technique_id}")
def attack_technique_findings(
    technique_id: str,
    tenant_slug: Optional[str] = Query(None),
    tenant_id: Optional[int] = Query(None),
    session: Session = Depends(get_sync_session),
):
    tenant = resolve_tenant(session, tenant_id=tenant_id, tenant_slug=tenant_slug, default_to_demo=True)
    findings = []
    for finding in session.query(BehaviorFinding).filter(BehaviorFinding.tenant_id == tenant.id).all():
        if any(item["technique_id"] == technique_id for item in _techniques(finding.payload or {})):
            findings.append(_finding_payload(finding))
    return {
        "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
        "technique_id": technique_id,
        "tactic": TECHNIQUE_TACTICS.get(technique_id, "Unknown"),
        "items": findings,
        "count": len(findings),
    }
