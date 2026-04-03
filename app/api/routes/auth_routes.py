"""Authentication APIs for private tenants."""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)
    tenant_slug: Optional[str] = None


@router.post("/token")
def login(
    request: LoginRequest,
    session: Session = Depends(get_sync_session),
):
    """Authenticate a private tenant user and return a JWT."""
    service = AuthService(session)
    return service.login(email=request.email, password=request.password, tenant_slug=request.tenant_slug)


@router.get("/me")
def me(
    token_data: TokenData = Depends(verify_token),
    session: Session = Depends(get_sync_session),
):
    """Return the current authenticated user."""
    service = AuthService(session)
    return service.me(token_data)
