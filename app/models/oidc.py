"""V5 W1a OIDC models — provider config catalog.

One row per registered OIDC provider (e.g. ``keycloak-prod``,
``authentik-staging``). Operators install/edit via the admin API; the
plaintext ``client_secret`` never touches the DB — we store a *reference*
(env var name or KMS path) and resolve it at runtime.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)

from app.core.database import Base
from app.core.time import utc_now


class OidcProvider(Base):
    """A configured external OIDC identity provider."""

    __tablename__ = "oidc_providers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(80), unique=True, nullable=False, index=True)
    issuer_url = Column(String(500), nullable=False)
    client_id = Column(String(255), nullable=False)
    # Reference (env var name or KMS URI) — never the plaintext secret.
    client_secret_ref = Column(String(255), nullable=False)
    redirect_uri = Column(String(500), nullable=False)
    scopes = Column(JSON, default=list, nullable=False)
    # claim_mappings keys (V5):
    #   role_claim          (default "groups")
    #   tenant_claim        (optional; absent => use default_tenant_id)
    #   username_claim      (default "preferred_username")
    #   email_claim         (default "email")
    #   role_value_map      {idp_value: sheshnaag_role_name}
    claim_mappings = Column(JSON, default=dict, nullable=False)
    default_tenant_id = Column(
        Integer, ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    is_active = Column(Boolean, nullable=False, default=True, server_default="1")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)
