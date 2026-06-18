"""Write-side backends for AI tool registry actions."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.malware_lab import AnalysisCase, SandboxProfile, Specimen
from app.models.sheshnaag import DetectionArtifact, LabRecipe, RecipeRevision
from app.models.v2 import Tenant
from app.services.detection_validator import DetectionValidatorService
from app.services.malware_lab_service import MalwareLabService

_AGENT_DETONATION_RECIPE_NAME = "__ai_agent_detonation__"


def _resolve_sandbox_profile(
    session: Session,
    tenant: Tenant,
    profile_id: str,
) -> SandboxProfile:
    lab = MalwareLabService(session)
    lab._ensure_default_sandbox_profiles(tenant)
    query = session.query(SandboxProfile).filter(SandboxProfile.tenant_id == tenant.id)
    row = None
    try:
        row = query.filter(SandboxProfile.id == int(profile_id)).first()
    except (TypeError, ValueError):
        row = query.filter(SandboxProfile.name == str(profile_id)).first()
    if row is None:
        raise ValueError("sandbox_profile_not_found")
    return row


def _ensure_agent_detonation_recipe(session: Session, tenant: Tenant) -> LabRecipe:
    existing = (
        session.query(LabRecipe)
        .filter(LabRecipe.tenant_id == tenant.id, LabRecipe.name == _AGENT_DETONATION_RECIPE_NAME)
        .first()
    )
    if existing is not None:
        return existing

    from app.services.sheshnaag_service import SheshnaagService

    svc = SheshnaagService(session)
    content = svc._prepare_recipe_content(
        {
            "provider": "lima",
            "image_profile": "secure_lima",
            "command": ["bash", "-lc", "echo sheshnaag-agent-detonation"],
            "network_policy": {"allow_egress_hosts": []},
            "collectors": ["process_tree", "file_diff", "network_metadata"],
            "teardown_policy": {"mode": "destroy_immediately", "ephemeral_workspace": True},
            "risk_level": "sensitive",
            "requires_acknowledgement": True,
        },
        None,
    )
    template = svc._ensure_lab_template(provider_name="lima", image_profile="secure_lima")
    recipe = LabRecipe(
        tenant_id=tenant.id,
        candidate_id=None,
        template_id=template.id,
        name=_AGENT_DETONATION_RECIPE_NAME,
        objective="Internal AI-agent malware detonation recipe.",
        provider="lima",
        status="approved",
        created_by="ai-agent",
        current_revision_number=1,
    )
    session.add(recipe)
    session.flush()
    signer = svc._attestation_signer_for_tenant(tenant)
    revision = RecipeRevision(
        recipe_id=recipe.id,
        revision_number=1,
        approval_state="approved",
        approved_by="ai-agent",
        approved_at=utc_now(),
        risk_level="sensitive",
        requires_acknowledgement=True,
        signed_digest=signer.sign(payload=content, signer="ai-agent")["sha256"],
        content=content,
    )
    session.add(revision)
    session.flush()
    return recipe


def propose_detection(
    session: Session,
    tenant: Tenant,
    *,
    kind: str,
    draft: dict[str, Any],
    actor: str,
) -> dict[str, Any]:
    draft_dict = draft if isinstance(draft, dict) else {"raw": str(draft)}
    validation = DetectionValidatorService(session).validate(tenant, kind=kind, draft=draft_dict)
    body_text = json.dumps(draft_dict, sort_keys=True, default=str)
    digest = hashlib.sha256(body_text.encode("utf-8")).hexdigest()[:16]

    artifact: dict[str, Any] | None = None
    run_id = draft_dict.get("run_id")
    case_id = draft_dict.get("case_id") or draft_dict.get("analysis_case_id")
    name = str(draft_dict.get("title") or draft_dict.get("name") or f"{kind}-proposal-{digest}")

    if run_id is not None:
        from app.models.sheshnaag import LabRun

        run = (
            session.query(LabRun)
            .filter(LabRun.tenant_id == tenant.id, LabRun.id == int(run_id))
            .first()
        )
        if run is None:
            validation.setdefault("errors", []).append("run_not_found")
        else:
            row = DetectionArtifact(
                run_id=run.id,
                artifact_type=kind,
                name=name,
                rule_body=body_text,
                status="proposed" if validation["valid"] else "draft",
                sha256=hashlib.sha256(body_text.encode("utf-8")).hexdigest(),
            )
            session.add(row)
            session.flush()
            artifact = {"family": "detection", "id": row.id, "run_id": run.id, "status": row.status}
    elif case_id is not None:
        case = (
            session.query(AnalysisCase)
            .filter(AnalysisCase.tenant_id == tenant.id, AnalysisCase.id == int(case_id))
            .first()
        )
        if case is None:
            validation.setdefault("errors", []).append("case_not_found")
        else:
            saved = MalwareLabService(session).create_prevention_artifact(
                tenant,
                analysis_case_id=case.id,
                artifact_type=kind,
                name=name,
                body=body_text,
                payload={
                    "source": "ai_tool.propose_detection",
                    "validator": validation["validator"],
                    "draft_digest": digest,
                },
            )
            artifact = {"family": "prevention", "id": saved["id"], "case_id": case.id, "status": saved["status"]}

    return {
        "tool": "propose_detection",
        "kind": kind,
        "draft_digest": digest,
        "validation": validation,
        "artifact": artifact,
        "actor": actor,
    }


def queue_specimen_detonation(
    session: Session,
    tenant: Tenant,
    *,
    specimen_id: str | int,
    profile_id: str,
    actor: str,
) -> dict[str, Any]:
    try:
        spec_id = int(specimen_id)
    except (TypeError, ValueError):
        return {
            "tool": "detonate_in_sandbox",
            "specimen_id": specimen_id,
            "profile_id": profile_id,
            "run_id": None,
            "status": "blocked",
            "error": "invalid_specimen_id",
        }

    specimen = (
        session.query(Specimen)
        .filter(Specimen.tenant_id == tenant.id, Specimen.id == spec_id)
        .first()
    )
    if specimen is None:
        return {
            "tool": "detonate_in_sandbox",
            "specimen_id": specimen_id,
            "profile_id": profile_id,
            "run_id": None,
            "status": "blocked",
            "error": "specimen_not_found",
        }

    try:
        profile = _resolve_sandbox_profile(session, tenant, profile_id)
    except ValueError:
        return {
            "tool": "detonate_in_sandbox",
            "specimen_id": specimen_id,
            "profile_id": profile_id,
            "run_id": None,
            "status": "blocked",
            "error": "sandbox_profile_not_found",
        }

    recipe = _ensure_agent_detonation_recipe(session, tenant)
    from app.services.sheshnaag_service import SheshnaagService

    svc = SheshnaagService(session)
    try:
        run = svc.launch_run(
            tenant,
            recipe_id=recipe.id,
            revision_number=recipe.current_revision_number,
            analyst_name=actor or "ai-agent",
            workstation={
                "hostname": "ai-agent",
                "os_family": "linux",
                "architecture": "x86_64",
                "fingerprint": "ai-agent",
            },
            launch_mode="execute",
            acknowledge_sensitive=True,
            analysis_mode="malware_detonation",
            sandbox_profile_id=profile.id,
            specimen_ids=[specimen.id],
            egress_mode=profile.egress_mode or "default_deny",
        )
    except ValueError as exc:
        return {
            "tool": "detonate_in_sandbox",
            "specimen_id": specimen_id,
            "profile_id": profile_id,
            "profile_name": profile.name,
            "run_id": None,
            "status": "blocked",
            "error": str(exc),
        }

    return {
        "tool": "detonate_in_sandbox",
        "specimen_id": specimen_id,
        "profile_id": str(profile.id),
        "profile_name": profile.name,
        "run_id": run.get("id"),
        "status": run.get("state", "queued"),
    }


def queue_authorized_offensive_run(
    session: Session,
    tenant: Tenant,
    *,
    target: str,
    recipe_id: str,
    actor: str,
) -> dict[str, Any]:
    from app.services.sheshnaag_service import SheshnaagService

    svc = SheshnaagService(session)
    try:
        recipe_pk = int(recipe_id)
    except (TypeError, ValueError):
        return {
            "tool": "run_authorized_offensive",
            "target": target,
            "recipe_id": recipe_id,
            "run_id": None,
            "status": "blocked",
            "error": "invalid_recipe_id",
        }

    try:
        recipe = svc._get_recipe(tenant, recipe_pk)
        revision = svc._get_recipe_revision(recipe.id, recipe.current_revision_number)
    except ValueError as exc:
        return {
            "tool": "run_authorized_offensive",
            "target": target,
            "recipe_id": recipe_id,
            "run_id": None,
            "status": "blocked",
            "error": str(exc),
        }

    if revision.approval_state != "approved":
        return {
            "tool": "run_authorized_offensive",
            "target": target,
            "recipe_id": recipe_id,
            "run_id": None,
            "status": "blocked",
            "error": "recipe_not_approved",
        }

    content = dict(revision.content or {})
    launch_mode = "execute" if content.get("launch_mode", "execute") != "simulated" else "simulated"
    try:
        run = svc.launch_run(
            tenant,
            recipe_id=recipe.id,
            revision_number=revision.revision_number,
            analyst_name=actor or "ai-agent",
            workstation={
                "hostname": "ai-agent",
                "os_family": "linux",
                "architecture": "x86_64",
                "fingerprint": "ai-agent-offensive",
            },
            launch_mode=launch_mode,
            acknowledge_sensitive=bool(revision.requires_acknowledgement),
            analysis_mode=str(content.get("analysis_mode") or "cve_validation"),
            sandbox_profile_id=content.get("sandbox_profile_id"),
            specimen_ids=list(content.get("specimen_ids") or []),
            egress_mode=content.get("egress_mode"),
        )
    except ValueError as exc:
        return {
            "tool": "run_authorized_offensive",
            "target": target,
            "recipe_id": recipe_id,
            "run_id": None,
            "status": "blocked",
            "error": str(exc),
        }

    run_row = svc._get_run(tenant, run["id"])
    run_row.manifest = {
        **dict(run_row.manifest or {}),
        "authorized_offensive_target": target,
        "offensive_research": True,
        "requested_by": actor or "ai-agent",
    }
    session.flush()

    return {
        "tool": "run_authorized_offensive",
        "target": target,
        "recipe_id": recipe_id,
        "run_id": run_row.id,
        "status": run_row.state,
    }
