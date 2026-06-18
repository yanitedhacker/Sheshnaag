"""Linear inbound webhook adapter.

Linear signs each webhook with HMAC-SHA256 over the raw body and
sends the hex digest in ``Linear-Signature``. No timestamp / replay
header is included; replay protection is up to the consumer (we
accept this — the JWT layer rejects stale-token replays elsewhere).

Reference: https://developers.linear.app/docs/graphql/webhooks
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


def verify_signature(headers: Mapping[str, str], body: bytes, secret: str) -> bool:
    signature = headers.get("linear-signature") or headers.get("Linear-Signature")
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def handle_event(
    session: Session, event: dict, *, default_actor_roles: list[str] | None = None
) -> dict:
    """Process a parsed Linear webhook payload.

    Recognized shapes:
      * Comment created with mention text
      * Issue updated with state change (mirror to lifecycle)
    """
    actor_roles = default_actor_roles or []

    action = event.get("action")
    data = event.get("data", {})
    payload_type = event.get("type")
    actor = (data.get("user") or {}).get("name") or "linear-user"

    # Comment with mention command.
    if payload_type == "Comment" and action == "create":
        text = data.get("body", "") or ""
        parsed = parse_mention(text)
        if parsed is None:
            return {"ok": True, "ignored": "no_mention_in_comment"}

        issue_id = (data.get("issue") or {}).get("id") or data.get("issueId")
        external_id = f"linear:{issue_id}" if issue_id else f"linear:{data.get('id')}"
        if parsed["kind"] == "link":
            upsert_link(
                session,
                case_id=parsed["case_id"],
                provider="linear",
                external_id=external_id,
                actor=actor,
            )
            return {"ok": True, "linked": parsed["case_id"]}
        if parsed["kind"] == "transition":
            return perform_transition(
                session,
                case_id=parsed["case_id"],
                to_state=parsed["to_state"],
                actor=f"linear:{actor}",
                actor_roles=actor_roles,
                reason=f"linear comment on {external_id}",
            )

    # Issue state update — reserved for V6 (status_sync). Acknowledge
    # the event without acting so Linear stops retrying.
    if payload_type == "Issue" and action == "update":
        return {"ok": True, "ignored": "issue_update_status_sync_v6"}

    return {"ok": True, "ignored": f"{payload_type}/{action}"}
