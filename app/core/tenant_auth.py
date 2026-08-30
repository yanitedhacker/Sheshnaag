"""Request-local authentication context for shared tenant authorization."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.security import TokenData, decode_token, token_data_from_payload

_UNBOUND = object()
_request_token: ContextVar[object | TokenData | None] = ContextVar(
    "sheshnaag_request_token",
    default=_UNBOUND,
)


@contextmanager
def bind_request_token(token_data: TokenData | None) -> Iterator[None]:
    """Bind one verified actor for the duration of an HTTP request."""

    token = _request_token.set(token_data)
    try:
        yield
    finally:
        _request_token.reset(token)


def current_request_token() -> tuple[bool, TokenData | None]:
    """Return whether HTTP auth context is bound and its verified actor."""

    value = _request_token.get()
    if value is _UNBOUND:
        return False, None
    return True, value if isinstance(value, TokenData) else None


class TenantAuthorizationContextMiddleware(BaseHTTPMiddleware):
    """Validate an optional Bearer token and bind it to tenant helpers."""

    async def dispatch(self, request: Request, call_next):
        token_data: TokenData | None = None
        authorization = request.headers.get("Authorization")
        if authorization:
            scheme, separator, credential = authorization.partition(" ")
            if scheme.lower() != "bearer" or not separator or not credential.strip():
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid authorization header"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            try:
                payload = decode_token(credential.strip())
                token_data = token_data_from_payload(payload)
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers=exc.headers,
                )

        with bind_request_token(token_data):
            return await call_next(request)
