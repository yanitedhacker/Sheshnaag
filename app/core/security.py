"""
JWT Authentication and Security utilities.

Author: Security Enhancement

Provides JWT-based authentication for API endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

try:
    from passlib.context import CryptContext
except ImportError as _passlib_import_err:  # pragma: no cover
    CryptContext = None
    _PASSLIB_IMPORT_ERROR: Optional[ImportError] = _passlib_import_err
else:
    _PASSLIB_IMPORT_ERROR = None

from app.core.config import settings

# Password hashing context.
#
# New hashes use Argon2 to avoid bcrypt's 72-byte input ceiling, while legacy
# bcrypt hashes remain verifiable during migration. We deliberately refuse to
# operate when passlib is missing — the previous code silently degraded to a
# plaintext compare, which is a critical auth downgrade and was flagged in the
# pre-pentest audit.
pwd_context = (
    CryptContext(
        schemes=["argon2", "bcrypt"],
        deprecated="auto",
    )
    if CryptContext is not None
    else None
)


def _require_pwd_context() -> "CryptContext":
    if pwd_context is None:
        raise RuntimeError(
            "passlib is required for password hashing/verification — install "
            "`passlib[argon2,bcrypt]` and `argon2-cffi`. Refusing to fall back "
            "to plaintext comparison."
        ) from _PASSLIB_IMPORT_ERROR
    return pwd_context

# HTTP Bearer token security scheme
security = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    """Token payload data."""
    username: Optional[str] = None
    user_id: Optional[int] = None
    scopes: List[str] = []
    memberships: List[dict] = []


class Token(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return _require_pwd_context().verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return _require_pwd_context().hash(password)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Payload data to encode
        expires_delta: Token expiration time

    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Args:
        token: JWT token string

    Returns:
        Decoded payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> TokenData:
    """
    Dependency to verify JWT token from request.

    Args:
        credentials: HTTP Authorization header credentials

    Returns:
        TokenData with username and scopes

    Raises:
        HTTPException: If authentication fails
    """
    if not settings.auth_enabled:
        # Auth disabled — return anonymous user with a scope set that depends
        # on the deployment environment. Only `development` keeps write scope
        # for local convenience; staging/production must enable real auth (the
        # startup validator already rejects auth_enabled=False in production,
        # but defense-in-depth here prevents accidental privilege handout if
        # the validator is bypassed).
        env = (settings.environment or "development").lower()
        if env == "development":
            return TokenData(username="anonymous", scopes=["read", "write"])
        return TokenData(username="anonymous", scopes=["read"])

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    username: str = payload.get("sub")

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scopes = payload.get("scopes", [])
    return TokenData(
        username=username,
        user_id=payload.get("user_id"),
        scopes=scopes,
        memberships=payload.get("memberships", []),
    )


def verify_token_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[TokenData]:
    """
    Optional token verification - returns None if no token provided.

    Useful for endpoints that work with or without authentication.
    """
    if credentials is None:
        return None

    try:
        return verify_token(credentials)
    except HTTPException:
        return None


def require_scope(required_scope: str):
    """
    Dependency factory to require a specific scope.

    Usage:
        @router.post("/admin", dependencies=[Depends(require_scope("admin"))])
    """
    def scope_checker(token_data: TokenData = Depends(verify_token)) -> TokenData:
        if required_scope not in token_data.scopes and "admin" not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{required_scope}' required"
            )
        return token_data
    return scope_checker


def require_capability(capability: str):
    """Dependency factory for the V4 capability-policy gate.

    Resolves the current actor from the JWT dependency, then delegates to
    :meth:`app.services.capability_policy.CapabilityPolicy.evaluate`. Raises
    ``HTTPException(403, detail="capability_required: <name>")`` when denied.

    Import of ``CapabilityPolicy`` is deferred to avoid a circular import
    (the service imports models which depend on Base, which may still be
    initializing when this module is first loaded).

    Usage::

        @router.post(
            "/runs",
            dependencies=[Depends(require_capability("dynamic_detonation"))],
        )
    """

    def _dep(
        token_data: TokenData = Depends(verify_token),
        session: Session = Depends(_session_dep),
    ) -> TokenData:
        from app.services.capability_policy import CapabilityPolicy  # lazy

        policy = CapabilityPolicy(session)
        scope = _scope_from_token(token_data)
        decision = policy.evaluate(
            capability=capability,
            scope=scope,
            actor=token_data.username or "anonymous",
        )
        if not decision.permitted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"capability_required: {capability}",
            )
        return token_data

    return _dep


def _scope_from_token(token_data: TokenData) -> dict:
    """Derive a capability-policy scope dict from a JWT token.

    We surface tenant context when present so the engine can honor per-tenant
    ``tenant_default_capabilities`` fast paths.
    """

    scope: dict = {}
    if token_data.memberships:
        tenant_ids = [
            m.get("tenant_id")
            for m in token_data.memberships
            if isinstance(m, dict) and m.get("tenant_id") is not None
        ]
        if len(tenant_ids) == 1:
            scope["tenant_id"] = tenant_ids[0]
    return scope


def _session_dep() -> "Session":
    # Lazily import the sync-session factory; this keeps circular imports at
    # bay and lets test suites swap the dependency via FastAPI's override.
    from app.core.database import get_sync_session

    yield from get_sync_session()


try:
    from sqlalchemy.orm import Session  # noqa: E402  (typed Depends target)
except Exception:  # pragma: no cover - sqlalchemy is a hard dep
    Session = Any  # type: ignore[assignment]
