"""V5 W2b — shared inbound webhook receiver.

One route, three providers. Signature verification happens BEFORE
JSON parsing so a malformed body never reaches our parser.

Each provider's webhook secret is read from an env var named
``SHESHNAAG_<PROVIDER>_WEBHOOK_SECRET`` (uppercase). Missing secret =
the receiver 503s (better than silently accepting unverified events).
"""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.services.integrations import SUPPORTED_PROVIDERS
from app.services.integrations import (
    jira_inbound,
    linear_inbound,
    slack_inbound,
)


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/v5/integrations/webhook",
    tags=["Sheshnaag V5 Integrations"],
)


_PROVIDER_DISPATCH = {
    "slack": slack_inbound,
    "linear": linear_inbound,
    "jira": jira_inbound,
}


def _secret_for(provider: str) -> str:
    env_var = f"SHESHNAAG_{provider.upper()}_WEBHOOK_SECRET"
    return os.environ.get(env_var, "")


@router.post("/{provider}")
async def receive(
    provider: str,
    request: Request,
    session: Session = Depends(get_sync_session),
) -> dict:
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown_provider:{provider}",
        )

    secret = _secret_for(provider)
    if not secret:
        # Don't accept unverifiable webhooks. Operator must configure
        # the secret to receive events.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"webhook_secret_unconfigured:{provider}",
        )

    raw_body = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}

    adapter = _PROVIDER_DISPATCH[provider]
    if not adapter.verify_signature(headers, raw_body, secret):
        # Constant-time check inside the adapter; we 401 here without
        # parsing JSON.
        logger.warning("rejected unverified webhook from %s", provider)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="signature_verification_failed",
        )

    try:
        payload = json.loads(raw_body.decode("utf-8") or "{}")
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"malformed_json:{e}",
        ) from e

    # Slack URL verification handshake — keep simple, no actor roles.
    if (
        provider == "slack"
        and isinstance(payload, dict)
        and payload.get("type") == "url_verification"
    ):
        return {"challenge": payload.get("challenge", "")}

    # The webhook caller has no Sheshnaag JWT, so it has no roles.
    # Use a configurable default for chat-driven actions; deployments
    # that want chat to drive transitions must explicitly grant a
    # service-bot role via SHESHNAAG_<PROVIDER>_ACTOR_ROLES (CSV).
    actor_roles_env = os.environ.get(
        f"SHESHNAAG_{provider.upper()}_ACTOR_ROLES", ""
    )
    actor_roles = [
        r.strip() for r in actor_roles_env.split(",") if r.strip()
    ]

    try:
        result = adapter.handle_event(
            session, payload, default_actor_roles=actor_roles
        )
    except Exception as e:  # pragma: no cover - infra
        logger.exception("inbound %s handler crashed", provider)
        raise HTTPException(
            status_code=500, detail=f"handler_failure:{type(e).__name__}"
        ) from e

    return result
