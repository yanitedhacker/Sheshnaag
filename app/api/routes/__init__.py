"""API route modules."""

from app.api.routes.cve_routes import router as cve_router
from app.api.routes.risk_routes import router as risk_router
from app.api.routes.asset_routes import router as asset_router
from app.api.routes.feed_routes import router as feed_router

__all__ = ["cve_router", "risk_router", "asset_router", "feed_router"]
