"""Shared helpers for inbound integration adapters."""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from app.models.integrations import CaseIntegrationLink
from app.services.case_workflow import (
    CaseLifecycleState,
    CaseWorkflowService,
    IllegalTransitionError,
    RoleNotPermittedError,
)

# Mention-action grammar:
#   @sheshnaag transition CASE-<id> to=<state>
#   @sheshnaag link CASE-<id>
_TRANSITION_RE = re.compile(
    r"@sheshnaag\s+transition\s+(?:case[-_]?)?(\d+)\s+to=([a-z_]+)",
    re.IGNORECASE,
)
_LINK_RE = re.compile(r"@sheshnaag\s+link\s+(?:case[-_]?)?(\d+)", re.IGNORECASE)


def lookup_case_by_link(session: Session, *, provider: str, external_id: str) -> int | None:
    row = (
        session.query(CaseIntegrationLink)
        .filter_by(provider=provider, external_id=external_id)
        .first()
    )
    return row.case_id if row is not None else None


def upsert_link(
    session: Session,
    *,
    case_id: int,
    provider: str,
    external_id: str,
    actor: str | None = None,
) -> CaseIntegrationLink:
    existing = (
        session.query(CaseIntegrationLink)
        .filter_by(provider=provider, external_id=external_id)
        .first()
    )
    if existing is not None:
        existing.case_id = case_id
        return existing
    row = CaseIntegrationLink(
        case_id=case_id,
        provider=provider,
        external_id=external_id,
        created_by=actor,
    )
    session.add(row)
    session.flush()
    return row


def parse_mention(text: str) -> dict | None:
    """Recognize ``@sheshnaag transition`` / ``@sheshnaag link`` mentions.

    Returns ``None`` if the text is not a mention command.
    """
    if not text:
        return None
    m = _TRANSITION_RE.search(text)
    if m:
        return {
            "kind": "transition",
            "case_id": int(m.group(1)),
            "to_state": m.group(2).lower(),
        }
    m = _LINK_RE.search(text)
    if m:
        return {"kind": "link", "case_id": int(m.group(1))}
    return None


def perform_transition(
    session: Session,
    *,
    case_id: int,
    to_state: str,
    actor: str,
    actor_roles: list[str],
    reason: str | None = None,
) -> dict:
    """Wrapper around CaseWorkflowService.transition with chat-friendly errors.

    Returns a dict for the inbound adapter to surface back to the user.
    Doesn't raise — the caller wants a stable shape to mirror to chat.
    """
    try:
        target = CaseLifecycleState(to_state)
    except ValueError:
        return {
            "ok": False,
            "error": f"unknown_state:{to_state}",
            "case_id": case_id,
        }

    workflow = CaseWorkflowService(session)
    try:
        audit = workflow.transition(
            case_id=case_id,
            to_state=target,
            actor=actor,
            actor_roles=actor_roles,
            reason=reason,
        )
    except IllegalTransitionError as e:
        return {"ok": False, "error": f"illegal:{e}", "case_id": case_id}
    except RoleNotPermittedError as e:
        return {"ok": False, "error": f"forbidden:{e}", "case_id": case_id}
    except Exception as e:
        return {
            "ok": False,
            "error": f"{type(e).__name__}:{e}",
            "case_id": case_id,
        }

    return {
        "ok": True,
        "case_id": audit.case_id,
        "from_state": audit.from_state,
        "to_state": audit.to_state,
        "actor": audit.actor,
        "role_at_transition": audit.role_at_transition,
    }
