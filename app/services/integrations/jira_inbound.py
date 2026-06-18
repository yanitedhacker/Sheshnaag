"""JIRA inbound webhook adapter.

JIRA Cloud signs webhooks via Atlassian Connect or via configurable
HMAC-SHA256 (the "Jira webhook secret" feature). We accept the
HMAC-SHA256 path; the signature header is configurable per
deployment (defaults to ``X-Hub-Signature-256`` since that's the
github-compatible convention several JIRA scripts use).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

from sqlalchemy.orm import Session

from app.services.integrations._common import (
    parse_mention,
    perform_transition,
    upsert_link,
)

_DEFAULT_SIG_HEADER = "x-hub-signature-256"


def verify_signature(
    headers: Mapping[str, str],
    body: bytes,
    secret: str,
    sig_header: str = _DEFAULT_SIG_HEADER,
) -> bool:
    signature = headers.get(sig_header) or headers.get(sig_header.title()) or ""
    # Accept either bare hex or sha256=<hex>.
    if signature.startswith("sha256="):
        signature = signature[len("sha256=") :]
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_event(
    session: Session, event: dict, *, default_actor_roles: list[str] | None = None
) -> dict:
    actor_roles = default_actor_roles or []

    issue_event = event.get("webhookEvent")
    issue = event.get("issue", {}) or {}
    fields = issue.get("fields", {}) or {}
    actor = (event.get("user") or {}).get("displayName") or "jira-user"

    # Comment events carry the comment under "comment" with body text.
    if issue_event == "comment_created" or event.get("comment"):
        comment = event.get("comment") or {}
        text = comment.get("body", "") or ""
        parsed = parse_mention(text)
        if parsed is None:
            return {"ok": True, "ignored": "no_mention_in_jira_comment"}

        issue_key = issue.get("key") or "JIRA-?"
        external_id = f"jira:{issue_key}"
        if parsed["kind"] == "link":
            upsert_link(
                session,
                case_id=parsed["case_id"],
                provider="jira",
                external_id=external_id,
                actor=actor,
            )
            return {"ok": True, "linked": parsed["case_id"]}
        if parsed["kind"] == "transition":
            return perform_transition(
                session,
                case_id=parsed["case_id"],
                to_state=parsed["to_state"],
                actor=f"jira:{actor}",
                actor_roles=actor_roles,
                reason=f"jira comment on {external_id}",
            )

    if issue_event == "jira:issue_updated":
        # Status sync deferred to V6 — same rationale as Linear.
        return {"ok": True, "ignored": "issue_updated_status_sync_v6"}

    return {"ok": True, "ignored": str(issue_event)}
