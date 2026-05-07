"""V5 W2b inbound integration adapters.

Each adapter (slack_inbound, linear_inbound, jira_inbound) exports:

  * ``verify_signature(headers, body, secret) -> bool`` — pre-parse
    HMAC check; the webhook route 401s a request before JSON-parsing
    if this returns False. Per Phase 0 §5: rolling our own webhook
    auth is a common foot-gun, so the verification is per-platform
    and uses constant-time comparison.

  * ``handle_event(session, event, secret) -> dict`` — interprets the
    parsed event payload. Returns a small dict describing what was
    done (e.g. ``{"action": "transitioned", "case_id": 1, "to":
    "review"}``). Errors raise ``IntegrationEventError``.

The shared route module imports the adapters on first hit so a
deployment without integration secrets configured still boots.
"""

from __future__ import annotations


class IntegrationEventError(RuntimeError):
    """Raised by handle_event when the payload references missing data
    or fails permission checks the platform can't surface itself."""


SUPPORTED_PROVIDERS = ("slack", "linear", "jira")
