"""API route modules."""

from app.api.routes.cve_routes import router as cve_router
from app.api.routes.risk_routes import router as risk_router
from app.api.routes.asset_routes import router as asset_router
from app.api.routes.feed_routes import router as feed_router
from app.api.routes.patch_routes import router as patch_router
from app.api.routes.workbench_routes import router as workbench_router
from app.api.routes.graph_routes import router as graph_router
from app.api.routes.simulation_routes import router as simulation_router
from app.api.routes.copilot_routes import router as copilot_router
from app.api.routes.model_routes import router as model_router
from app.api.routes.import_routes import router as import_router
from app.api.routes.governance_routes import router as governance_router
from app.api.routes.auth_routes import router as auth_router
from app.api.routes.tenant_routes import router as tenant_router

__all__ = [
    "cve_router",
    "risk_router",
    "asset_router",
    "feed_router",
    "patch_router",
    "workbench_router",
    "graph_router",
    "simulation_router",
    "copilot_router",
    "model_router",
    "import_router",
    "governance_router",
    "auth_router",
    "tenant_router",
]
