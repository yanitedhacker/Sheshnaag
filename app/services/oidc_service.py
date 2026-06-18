"""V5 W1a OIDC service — provider config + JIT + claim→role mapping.

The split with :mod:`app.api.routes.auth_oidc` is:

  * This service knows the database, knows the V5 role catalog, and
    knows the local TenantUser/TenantMembership shape. It does *not*
    speak HTTP.
  * The route layer drives the OIDC handshake (authlib) and calls into
    this service with the resulting ID-token claims.

Why split: keeps the service unit-testable without a live IdP.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.models.oidc import OidcProvider
from app.models.v2 import Tenant, TenantMembership, TenantUser
from app.services.rbac import RbacService

_VALID_V5_ROLES = frozenset({"read_only", "analyst", "senior_analyst", "reviewer", "lab_lead"})

_DEFAULT_SCOPES = ("openid", "email", "profile", "groups")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OidcConfigError(ValueError):
    """Provider config is malformed or duplicates an existing name."""


class OidcCallbackError(RuntimeError):
    """The OIDC callback could not be completed (invalid state, etc.)."""


class OidcProviderNotFoundError(LookupError):
    """The named provider is not registered."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class OidcService:
    """Provider catalog CRUD + JIT user provisioning + claim→role mapping."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ----- provider catalog ----------------------------------------------

    def list_providers(self) -> list[OidcProvider]:
        return self._session.query(OidcProvider).order_by(OidcProvider.name).all()

    def get_provider(self, name: str) -> OidcProvider:
        row = self._session.query(OidcProvider).filter_by(name=name).first()
        if row is None:
            raise OidcProviderNotFoundError(name)
        return row

    def install_provider(
        self,
        *,
        name: str,
        issuer_url: str,
        client_id: str,
        client_secret_ref: str,
        redirect_uri: str,
        scopes: Iterable[str] | None = None,
        claim_mappings: dict | None = None,
        default_tenant_id: int | None = None,
        notes: str | None = None,
    ) -> OidcProvider:
        if not name or not issuer_url or not client_id:
            raise OidcConfigError("name, issuer_url, client_id required")
        if self._session.query(OidcProvider).filter_by(name=name).first() is not None:
            raise OidcConfigError(f"provider_exists:{name}")

        merged_mappings = {
            "role_claim": "groups",
            "username_claim": "preferred_username",
            "email_claim": "email",
            "role_value_map": {},
        }
        if claim_mappings:
            merged_mappings.update(claim_mappings)

        row = OidcProvider(
            name=name,
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret_ref=client_secret_ref,
            redirect_uri=redirect_uri,
            scopes=list(scopes or _DEFAULT_SCOPES),
            claim_mappings=merged_mappings,
            default_tenant_id=default_tenant_id,
            notes=notes,
            is_active=True,
        )
        self._session.add(row)
        self._session.flush()
        return row

    @staticmethod
    def resolve_client_secret(provider: OidcProvider) -> str:
        """Resolve the plaintext client secret from its env-var ref.

        Format: ``client_secret_ref`` is the *name* of an env var (e.g.
        ``OIDC_KEYCLOAK_CLIENT_SECRET``). KMS resolution is V6+.
        """
        ref = provider.client_secret_ref
        if not ref:
            raise OidcConfigError("client_secret_ref_empty")
        value = os.environ.get(ref)
        if not value:
            raise OidcConfigError(f"client_secret_env_unset:{ref}")
        return value

    # ----- claim mapping --------------------------------------------------

    def map_claims_to_roles(self, provider: OidcProvider, claims: dict) -> list[str]:
        """Return the V5 role names produced by the IdP claim mapping.

        The IdP delivers a list (or single string) under the configured
        ``role_claim`` (default ``groups``). Each value is run through
        ``role_value_map`` to translate IdP-side names to V5 role
        names. Anything that maps to a non-V5 role name is dropped.
        """
        role_claim = provider.claim_mappings.get("role_claim", "groups")
        value_map: dict = provider.claim_mappings.get("role_value_map", {})
        rbac = RbacService(self._session)

        raw = claims.get(role_claim, [])
        if isinstance(raw, str):
            raw_list = [raw]
        elif isinstance(raw, list):
            raw_list = [str(x) for x in raw]
        else:
            raw_list = []

        mapped: list[str] = []
        seen: set[str] = set()
        for v in raw_list:
            translated = value_map.get(v, v)
            if translated in _VALID_V5_ROLES and translated not in seen:
                if rbac.validate_role_name(translated):
                    mapped.append(translated)
                    seen.add(translated)
        return mapped

    def map_claims_to_tenant(self, provider: OidcProvider, claims: dict) -> int | None:
        """Return the tenant_id this user should land in.

        Order:
          1. Provider's ``tenant_claim`` if set and present in claims.
          2. Provider's ``default_tenant_id``.
          3. None (caller decides — likely 401).
        """
        tenant_claim = provider.claim_mappings.get("tenant_claim")
        if tenant_claim:
            value = claims.get(tenant_claim)
            if value is not None:
                # Try lookup by id first, then by slug.
                if isinstance(value, int):
                    row = self._session.query(Tenant).filter_by(id=value).first()
                    if row is not None:
                        return row.id
                row = self._session.query(Tenant).filter_by(slug=str(value)).first()
                if row is not None:
                    return row.id
        return provider.default_tenant_id

    # ----- JIT user provisioning -----------------------------------------

    def jit_provision(self, provider: OidcProvider, claims: dict) -> tuple[TenantUser, list[dict]]:
        """Get-or-create the TenantUser and ensure a TenantMembership row.

        Returns ``(user, memberships)`` where memberships is the
        JSON-serializable shape that lands inside the Sheshnaag JWT.
        """
        username_claim = provider.claim_mappings.get("username_claim", "preferred_username")
        email_claim = provider.claim_mappings.get("email_claim", "email")
        username = claims.get(username_claim) or claims.get("sub")
        email = claims.get(email_claim) or username
        if not username or not email:
            raise OidcCallbackError("missing_identity_claims")

        user = self._session.query(TenantUser).filter_by(email=email).first()
        if user is None:
            # JIT provisioned users have a placeholder password hash —
            # they can't log in via the password path.
            user = TenantUser(
                email=email,
                full_name=claims.get("name") or username,
                password_hash="!oidc-jit",
                is_active=True,
                is_system=False,
            )
            self._session.add(user)
            self._session.flush()

        # Determine target tenant + role from claims.
        tenant_id = self.map_claims_to_tenant(provider, claims)
        if tenant_id is None:
            raise OidcCallbackError("no_tenant_assignable")

        roles = self.map_claims_to_roles(provider, claims)
        primary_role = roles[0] if roles else "read_only"

        membership = (
            self._session.query(TenantMembership)
            .filter_by(user_id=user.id, tenant_id=tenant_id)
            .first()
        )
        if membership is None:
            membership = TenantMembership(
                tenant_id=tenant_id,
                user_id=user.id,
                role=primary_role,
                scopes=[],
            )
            self._session.add(membership)
        else:
            # Update role on each login so claim changes propagate.
            membership.role = primary_role
        self._session.flush()

        memberships_payload = [{"tenant_id": tenant_id, "role": primary_role, "scopes": []}]
        return user, memberships_payload

    # ----- session token mint --------------------------------------------

    def mint_session_token(
        self,
        user: TenantUser,
        roles: list[str],
        memberships: list[dict],
    ) -> str:
        """Mint a Sheshnaag JWT for the JIT-provisioned user.

        The token carries the union of memberships' roles and any
        explicit roles claim (W0a's verify_token unions both, but we
        explicitly include here so service-to-service callers see them
        even without a membership row).
        """
        payload = {
            "sub": user.email,
            "user_id": user.id,
            "scopes": [],
            "memberships": memberships,
            "roles": roles,
        }
        return create_access_token(payload)
