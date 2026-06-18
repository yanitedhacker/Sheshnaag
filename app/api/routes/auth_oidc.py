"""V5 W1a OIDC authentication routes.

Three public endpoints behind the ``/api/v5/auth/oidc`` prefix:

  * ``GET  /providers``               — list configured providers
  * ``GET  /{provider}/login``        — issue a redirect URL into the IdP
  * ``GET  /{provider}/callback``     — exchange the auth code, JIT-provision,
                                        mint a Sheshnaag JWT, return it

Discovery, JWKS rotation, and ID-token validation use authlib. authlib
is imported lazily so the rest of the app remains bootable in
deployments where OIDC is not configured (the import only fires on the
first hit to one of these routes).
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.services.oidc_service import (
    OidcCallbackError,
    OidcConfigError,
    OidcProviderNotFoundError,
    OidcService,
)

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/v5/auth/oidc", tags=["Sheshnaag V5 OIDC"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ProviderSummary(BaseModel):
    name: str
    issuer_url: str
    redirect_uri: str
    is_active: bool


class LoginUrlResponse(BaseModel):
    provider: str
    authorize_url: str
    state: str


class CallbackResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_email: str
    roles: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _discover(issuer_url: str) -> dict:
    """Fetch the IdP's discovery document. Lazy authlib import."""
    import requests

    discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    r = requests.get(discovery_url, timeout=10)
    r.raise_for_status()
    return r.json()


def _exchange_code_for_tokens(
    *,
    discovery: dict,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict:
    import requests

    token_url = discovery["token_endpoint"]
    r = requests.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Accept": "application/json"},
        timeout=15,
    )
    if r.status_code != 200:
        raise OidcCallbackError(f"token_endpoint_error:{r.status_code}:{r.text[:200]}")
    return r.json()


def _verify_id_token(
    *,
    id_token: str,
    discovery: dict,
    client_id: str,
    expected_issuer: str,
) -> dict:
    """Verify ID token signature against IdP's JWKS and return claims.

    authlib's JsonWebToken handles JWKS lookup + alg whitelisting; we
    pin the issuer + audience checks explicitly.
    """
    import requests
    from authlib.jose import JsonWebToken

    jwks_url = discovery["jwks_uri"]
    jwks = requests.get(jwks_url, timeout=10).json()

    jwt = JsonWebToken(["RS256", "ES256"])
    claims = jwt.decode(id_token, key=jwks)
    claims.validate()  # exp, iat, nbf

    if claims.get("iss") != expected_issuer:
        raise OidcCallbackError(f"issuer_mismatch:{claims.get('iss')}!={expected_issuer}")
    aud = claims.get("aud")
    if isinstance(aud, list):
        if client_id not in aud:
            raise OidcCallbackError(f"audience_mismatch:{aud}")
    elif aud != client_id:
        raise OidcCallbackError(f"audience_mismatch:{aud}")

    return dict(claims)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=list[ProviderSummary])
def list_providers(
    _td: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
) -> list[ProviderSummary]:
    svc = OidcService(session)
    return [
        ProviderSummary(
            name=p.name,
            issuer_url=p.issuer_url,
            redirect_uri=p.redirect_uri,
            is_active=p.is_active,
        )
        for p in svc.list_providers()
        if p.is_active
    ]


@router.get("/{provider}/login", response_model=LoginUrlResponse)
def login(
    provider: str,
    session: Session = Depends(get_sync_session),
) -> LoginUrlResponse:
    """Build the authorize URL the browser should redirect to.

    No JWT required — this is the entry point of the login flow. The
    caller is the unauthenticated browser. The ``state`` param is a
    CSRF guard the caller stores client-side and re-presents at callback.
    """
    svc = OidcService(session)
    try:
        prov = svc.get_provider(provider)
    except OidcProviderNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    if not prov.is_active:
        raise HTTPException(status_code=400, detail="provider_disabled")

    discovery = _discover(prov.issuer_url)
    state_value = secrets.token_urlsafe(32)
    scopes = " ".join(prov.scopes or ["openid", "email", "profile"])

    from urllib.parse import urlencode

    authorize_url = (
        discovery["authorization_endpoint"]
        + "?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": prov.client_id,
                "redirect_uri": prov.redirect_uri,
                "scope": scopes,
                "state": state_value,
            }
        )
    )
    return LoginUrlResponse(provider=prov.name, authorize_url=authorize_url, state=state_value)


@router.get("/{provider}/callback", response_model=CallbackResponse)
def callback(
    provider: str,
    code: str,
    state: str | None = None,
    session: Session = Depends(get_sync_session),
) -> CallbackResponse:
    """Exchange the auth code, JIT-provision the user, mint a Sheshnaag JWT.

    State validation is the *caller*'s responsibility (compare client-
    side stored state to this query param) — we do not persist state
    server-side because the legitimate flow never hits this endpoint
    with a state we minted.
    """
    svc = OidcService(session)
    try:
        prov = svc.get_provider(provider)
    except OidcProviderNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    try:
        client_secret = OidcService.resolve_client_secret(prov)
    except OidcConfigError as e:
        raise HTTPException(status_code=500, detail=f"provider_misconfigured:{e}") from e

    discovery = _discover(prov.issuer_url)
    try:
        tokens = _exchange_code_for_tokens(
            discovery=discovery,
            client_id=prov.client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=prov.redirect_uri,
        )
    except OidcCallbackError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e

    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=401, detail="no_id_token_in_response")

    expected_issuer = discovery["issuer"]
    try:
        claims = _verify_id_token(
            id_token=id_token,
            discovery=discovery,
            client_id=prov.client_id,
            expected_issuer=expected_issuer,
        )
    except OidcCallbackError as e:
        raise HTTPException(status_code=401, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"id_token_invalid:{type(e).__name__}") from e

    try:
        user, memberships = svc.jit_provision(prov, claims)
    except OidcCallbackError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    roles = svc.map_claims_to_roles(prov, claims)
    if not roles:
        # Default to read_only — strictly safer than dropping the login
        # silently. Operator can map IdP groups explicitly to escalate.
        roles = ["read_only"]

    access_token = svc.mint_session_token(user, roles, memberships)
    return CallbackResponse(
        access_token=access_token,
        user_email=user.email,
        roles=roles,
    )
