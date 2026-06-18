"""V6 offensive capability API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.core.tenancy import resolve_tenant
from app.lab.research.crash_triage import CrashTriage
from app.lab.research.debugger import DebuggerOrchestrator
from app.lab.research.fuzzing import FuzzingHarness
from app.services.exploit_validator import ExploitValidator
from app.services.purple_team_service import PurpleTeamService

router = APIRouter(prefix="/api/v6", tags=["Sheshnaag V6"])


class ExploitValidationRequest(BaseModel):
    tenant_slug: str | None = None
    cve_id: str
    source: str = "manual"
    scope: dict[str, Any] = Field(default_factory=dict)
    vulnerable_image_digest: str
    patched_image_digest: str
    poc_body: str | None = None


class PurpleReplayRequest(BaseModel):
    tenant_slug: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    technique_ids: list[str] | None = None
    use_caldera: bool = False


class ResearchFuzzRequest(BaseModel):
    scope: dict[str, Any] = Field(default_factory=dict)
    target_binary: str
    engine: str = "afl"


@router.post("/exploit-validation/runs")
def create_exploit_validation(
    body: ExploitValidationRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    tenant = resolve_tenant(session, tenant_slug=body.tenant_slug, default_to_demo=True)
    actor = token_data.username or "anonymous"
    scope = dict(body.scope)
    if body.poc_body:
        scope["poc_body"] = body.poc_body
    try:
        row = ExploitValidator(session).queue_validation(
            tenant_id=tenant.id,
            actor=actor,
            cve_id=body.cve_id,
            source=body.source,
            scope=scope,
            vulnerable_image_digest=body.vulnerable_image_digest,
            patched_image_digest=body.patched_image_digest,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    manifest = ExploitValidator.build_manifest(row)
    return {
        "run_uuid": row.run_uuid,
        "status": row.status,
        "manifest_digest": manifest.manifest_digest,
        "manifest": row.manifest,
    }


@router.post("/purple-team/replay")
def purple_team_replay(
    body: PurpleReplayRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    actor = token_data.username or "anonymous"
    try:
        return PurpleTeamService(session).run_replay(
            actor=actor,
            scope=body.scope,
            technique_ids=body.technique_ids,
            use_caldera=body.use_caldera,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/research/fuzz")
def research_fuzz(
    body: ResearchFuzzRequest,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    from app.services.capability_policy import CapabilityPolicy

    actor = token_data.username or "anonymous"
    decision = CapabilityPolicy(session).evaluate(
        capability="offensive_research", scope=body.scope, actor=actor
    )
    if not decision.permitted:
        raise HTTPException(status_code=403, detail=decision.reason)
    fuzz = FuzzingHarness().launch(target_binary=body.target_binary, engine=body.engine)
    triage = CrashTriage()
    fuzz["triage"] = [triage.triage(crash=c) for c in fuzz.get("crashes", [])]
    return fuzz


@router.post("/research/debug")
def research_debug(
    platform: str,
    pid: int,
    session: Session = Depends(get_sync_session),
    token_data: TokenData = Depends(verify_token),
):
    from app.services.capability_policy import CapabilityPolicy

    actor = token_data.username or "anonymous"
    decision = CapabilityPolicy(session).evaluate(
        capability="offensive_research", scope={}, actor=actor
    )
    if not decision.permitted:
        raise HTTPException(status_code=403, detail=decision.reason)
    return DebuggerOrchestrator().attach(platform=platform, pid=pid)
