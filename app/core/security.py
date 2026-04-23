"""
JWT Authentication and Security utilities.

Author: Security Enhancement

Provides JWT-based authentication for API endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

try:
    from passlib.context import CryptContext
except ImportError:  # pragma: no cover - environment-specific fallback
    CryptContext = None

from app.core.config import settings

# Password hashing context
#
# New hashes use Argon2 to avoid bcrypt's 72-byte input ceiling, while legacy
# bcrypt hashes remain verifiable during migration.
pwd_context = (
    CryptContext(
        schemes=["argon2", "bcrypt"],
        deprecated="auto",
    )
    if CryptContext is not None
    else None
)

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
    if pwd_context is None:
        return plain_password == hashed_password
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    if pwd_context is None:
        return password
    return pwd_context.hash(password)


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
        # Auth disabled - return anonymous user
        return TokenData(username="anonymous", scopes=["read", "write"])

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
