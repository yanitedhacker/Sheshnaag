"""
Main FastAPI application.

Author: Archishman Paul

===========================================================================
   ______     ______     ______     ______   __  __     ______     ______  
  /\  ___\   /\  == \   /\  ___\   /\__  _\ /\ \_\ \   /\  == \   /\  ___\ 
  \ \ \____  \ \  __<   \ \  __\   \/_/\ \/ \ \  __ \  \ \  __<   \ \ \____ 
   \ \_____\  \ \_____\  \ \_____\    \ \_\  \ \_\ \_\  \ \_\ \_\  \ \_____\\
    \/_____/   \/_____/   \/_____/     \/_/   \/_/\/_/   \/_/ /_/   \/_____/
                                                                            
           T H R E A T   R A D A R   -   A I   P O W E R E D
===========================================================================

Welcome to CVE Threat Radar!

This is where everything comes together - the API endpoints, the ML models,
the database, and the dashboard. FastAPI was chosen for its async support,
automatic OpenAPI docs, and blazing fast performance.

Built with passion by Archishman Paul.
===========================================================================
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from prometheus_client import make_asgi_app

from app.core.config import settings
from app.core.database import engine, Base
from app.api.routes import cve_router, risk_router, asset_router, feed_router

# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="""
    AI-Driven CVE Threat Radar & Patch Prioritization Engine
    
    This API provides:
    - CVE vulnerability intelligence from multiple threat feeds
    - ML-based exploit probability prediction
    - Risk scoring and patch prioritization
    - Asset vulnerability management
    - Explainable AI-driven recommendations
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Include routers
app.include_router(cve_router)
app.include_router(risk_router)
app.include_router(asset_router)
app.include_router(feed_router)

# Mount static files for frontend
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/dashboard", tags=["Frontend"])
async def serve_dashboard():
    """Serve the frontend dashboard."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"error": "Dashboard not found"}


@app.get("/", tags=["Health"])
def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "healthy",
        "docs": "/docs",
        "endpoints": {
            "cves": "/api/cves",
            "risk": "/api/risk",
            "assets": "/api/assets",
            "feeds": "/api/feeds",
            "metrics": "/metrics"
        }
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "environment": settings.environment,
        "version": settings.app_version
    }


@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard_data():
    """
    Get aggregated dashboard data.
    
    Combines multiple data sources for the main dashboard view.
    """
    from app.core.database import SessionLocal
    from app.services.risk_aggregator import RiskAggregator
    from app.services.cve_service import CVEService
    from app.services.asset_service import AssetService
    
    session = SessionLocal()
    try:
        risk_aggregator = RiskAggregator(session)
        cve_service = CVEService(session)
        asset_service = AssetService(session)
        
        return {
            "risk_summary": risk_aggregator.get_risk_summary(),
            "top_priorities": risk_aggregator.get_top_priorities(limit=10),
            "cve_statistics": cve_service.get_cve_statistics(),
            "trending_cves": cve_service.get_trending_cves(limit=5),
            "heatmap_data": risk_aggregator.get_risk_heatmap_data(),
            "organization_summary": asset_service.get_organization_risk_summary()
        }
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )
