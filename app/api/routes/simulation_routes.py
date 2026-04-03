"""What-if simulation APIs."""

from typing import List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_sync_session
from app.core.security import TokenData, verify_token_optional
from app.core.tenancy import resolve_tenant
from app.services.auth_service import AuthService
from app.services.simulation_service import SimulationService

router = APIRouter(prefix="/api/simulations", tags=["Simulations"])


class RiskSimulationRequest(BaseModel):
    tenant_slug: Optional[str] = Field(None, description="Tenant slug. Defaults to demo-public.")
    tenant_id: Optional[int] = Field(None, description="Tenant id for private workspaces.")
    name: Optional[str] = None
    delay_days: int = Field(0, ge=0, le=365)
    downtime_budget_minutes: int = Field(60, ge=0, le=1440)
    team_capacity: int = Field(3, ge=1, le=100)
    allowed_windows: Optional[List[str]] = None
    public_exposure_weight: float = Field(1.0, ge=0.0, le=3.0)
    crown_jewel_weight: float = Field(1.0, ge=0.0, le=3.0)
    compensating_controls: bool = False


@router.post("/risk")
def run_risk_simulation(
    request: RiskSimulationRequest,
    session: Session = Depends(get_sync_session),
    token_data: Optional[TokenData] = Depends(verify_token_optional),
):
    """Run a what-if risk simulation and persist it for writable tenants."""
    auth_service = AuthService(session)
    if request.tenant_id is None and request.tenant_slug is None and token_data and token_data.memberships:
        tenant = auth_service.resolve_private_tenant(token_data=token_data)
    else:
        tenant = resolve_tenant(
            session,
            tenant_id=request.tenant_id,
            tenant_slug=request.tenant_slug,
            default_to_demo=True,
        )
    if not tenant.is_demo:
        auth_service.assert_tenant_access(tenant, token_data, access="write")
    service = SimulationService(session)
    return service.run_risk_simulation(
        tenant,
        parameters=request.model_dump(exclude_none=True),
        persist=not tenant.is_read_only,
    )
