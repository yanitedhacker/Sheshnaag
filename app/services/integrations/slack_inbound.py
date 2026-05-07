"""Slack inbound webhook adapter.

Slack signs each request with HMAC-SHA256 over
``v0:{timestamp}:{body}`` and includes the signature as
``X-Slack-Signature: v0=<hex>``. Replay protection: reject if the
timestamp is more than 5 minutes from now.

Reference: https://api.slack.com/authentication/verifying-requests-from-slack
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Mapping, Optional

from sqlalchemy.orm import Session

from app.services.integrations._common import (
    lookup_case_by_link,
    parse_mention,
    perform_transition,
    upsert_link,
)


_REPLAY_WINDOW_SECONDS = 60 * 5


def verify_signature(headers: Mapping[str, str], body: bytes, secret: str) -> bool:
    timestamp = headers.get("x-slack-request-timestamp") or headers.get(
        "X-Slack-Request-Timestamp"
    )
    signature = headers.get("x-slack-signature") or headers.get(
        "X-Slack-Signature"
    )
    if not timestamp or not signature or not secret:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > _REPLAY_WINDOW_SECONDS:
        return False

    base = f"v0:{timestamp}:".encode("utf-8") + body
    expected = (
        "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    )
    return hmac.compare_digest(expected, signature)


def handle_event(
    session: Session, event: dict, *, default_actor_roles: Optional[list[str]] = None
) -> dict:
    """Process a parsed Slack event payload.

    Slack delivers a small set of event shapes; we recognize:
      * ``app_mention``: text contains a mention command we parse
      * ``message`` with bot-targeted text (same parser)
    """
    actor_roles = default_actor_roles or []

    # Slack URL verification handshake.
    if event.get("type") == "url_verification":
        return {"challenge": event.get("challenge", "")}

    inner = event.get("event", {})
    event_type = inner.get("type")
    if event_type not in {"app_mention", "message"}:
        return {"ok": True, "ignored": event_type}

    text = inner.get("text") or ""
    parsed = parse_mention(text)
    if parsed is None:
        return {"ok": True, "ignored": "no_mention_command"}

    user = inner.get("user") or "slack-user"
    channel = inner.get("channel") or "slack-channel"
    ts = inner.get("ts") or "0"
    external_id = f"{channel}:{ts}"

    if parsed["kind"] == "link":
        upsert_link(
            session,
            case_id=parsed["case_id"],
            provider="slack",
            external_id=external_id,
            actor=user,
        )
        return {"ok": True, "linked": parsed["case_id"]}

    if parsed["kind"] == "transition":
        result = perform_transition(
            session,
            case_id=parsed["case_id"],
            to_state=parsed["to_state"],
            actor=f"slack:{user}",
            actor_roles=actor_roles,
            reason=f"slack message {external_id}",
        )
        return result

    return {"ok": False, "error": "unrecognized_command"}
