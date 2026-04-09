"""Main FastAPI application for Project Sheshnaag."""

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import redis
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from prometheus_client import make_asgi_app
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings, validate_settings_for_startup
from app.core.database import engine, Base, SessionLocal
from app.core.logging import configure_logging
from app.core.rate_limit import rate_limiter
from app.core.security import decode_token
from app.api.routes import (
    asset_router,
    artifact_router,
    auth_router,
    candidate_router,
    copilot_router,
    cve_router,
    disclosure_router,
    evidence_router,
    feed_router,
    governance_router,
    graph_router,
    import_router,
    intel_router,
    ledger_router,
    model_router,
    patch_router,
    provenance_router,
    risk_router,
    recipe_router,
    run_router,
    simulation_router,
    supply_chain_router,
    template_router,
    tenant_router,
    workbench_router,
)
from app.ingestion.scheduler import FeedScheduler
from app.ml.model_registry import preload_models
from app.services.demo_seed_service import DemoSeedService
from app.models.v2 import (
    AttackTechnique,
    EPSSSnapshot,
    ExposureGraphEdge,
    ExposureGraphNode,
    KEVEntry,
    KnowledgeChunk,
    KnowledgeDocument,
)

# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
FRONTEND_DIST_DIR = FRONTEND_DIR / "dist"

# Configure logging
configure_logging(settings.debug)
logger = logging.getLogger(__name__)
feed_scheduler = FeedScheduler()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add request ID to all requests for tracing and debugging."""

    async def dispatch(self, request: Request, call_next):
        # Get request ID from header or generate new one
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Store in request state for access in handlers
        request.state.request_id = request_id

        response = await call_next(request)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # HSTS header (only in production with HTTPS)
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy (relaxed for dashboard)
        if not request.url.path.startswith("/dashboard"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting if disabled
        if not settings.rate_limit_enabled:
            return await call_next(request)

        # Skip rate limiting for health checks and static files
        skip_paths = {"/health", "/", "/metrics", "/docs", "/redoc", "/openapi.json"}
        if request.url.path in skip_paths or request.url.path.startswith("/static"):
            return await call_next(request)

        # Check rate limit
        try:
            await rate_limiter.check(request)
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail},
                headers=e.headers
            )

        response = await call_next(request)

        # Add rate limit headers
        remaining = rate_limiter.get_remaining(request)
        response.headers["X-RateLimit-Limit"] = str(remaining["limit_per_minute"])
        response.headers["X-RateLimit-Remaining"] = str(remaining["remaining_per_minute"])

        return response


class MetricsAuthMiddleware(BaseHTTPMiddleware):
    """Protect /metrics endpoint when enabled."""

    async def dispatch(self, request: Request, call_next):
        if settings.metrics_enabled and settings.metrics_require_auth and request.url.path == "/metrics":
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            token = auth_header.split(" ", 1)[1].strip()
            try:
                decode_token(token)
            except HTTPException as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        return await call_next(request)


def check_redis_connection() -> bool:
    """Check if Redis is available and responding."""
    try:
        r = redis.from_url(settings.redis_url, socket_connect_timeout=2)
        r.ping()
        return True
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Deployment profile: {settings.deployment_profile}")

    # Validate settings
    try:
        validate_settings_for_startup()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        raise

    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")

    # Seed demo-public tenant and baseline v2 data
    session = SessionLocal()
    try:
        DemoSeedService(session).seed()
        session.commit()
    finally:
        session.close()
    logger.info("Demo seed verified")

    # Preload ML models
    preload_models()

    # Start ingestion scheduler
    feed_scheduler.start()
    logger.info("Feed scheduler started")

    yield

    # Shutdown
    logger.info("Shutting down application")
    feed_scheduler.shutdown()
    logger.info("Feed scheduler stopped")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="""
    Project Sheshnaag defensive validation platform

    This API provides:
    - CVE vulnerability intelligence from multiple threat feeds
    - explainable research candidate scoring
    - constrained Kali-backed validation planning
    - evidence, artifact, and provenance workflows
    - disclosure bundle and analyst ledger surfaces

    ## Authentication

    When authentication is enabled, all API endpoints require a valid JWT token.
    Include the token in the Authorization header: `Bearer <token>`
    """,
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add request ID middleware (first, so all other middleware can use it)
app.add_middleware(RequestIDMiddleware)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)
app.add_middleware(MetricsAuthMiddleware)

# Add CORS middleware with restricted origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-Request-ID"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-Request-ID"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Mount Prometheus metrics (with optional protection)
if settings.metrics_enabled:
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)

# Include routers
app.include_router(cve_router)
app.include_router(risk_router)
app.include_router(asset_router)
app.include_router(intel_router)
app.include_router(candidate_router)
app.include_router(recipe_router)
app.include_router(run_router)
app.include_router(evidence_router)
app.include_router(artifact_router)
app.include_router(provenance_router)
app.include_router(ledger_router)
app.include_router(disclosure_router)
app.include_router(feed_router)
app.include_router(patch_router)
app.include_router(workbench_router)
app.include_router(graph_router)
app.include_router(simulation_router)
app.include_router(copilot_router)
app.include_router(model_router)
app.include_router(import_router)
app.include_router(governance_router)
app.include_router(auth_router)
app.include_router(tenant_router)
app.include_router(supply_chain_router)
app.include_router(template_router)

# Mount static files for frontend
if FRONTEND_DIST_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIST_DIR)), name="static")


@app.get("/dashboard", tags=["Frontend"])
async def serve_dashboard():
    """Serve the frontend dashboard."""
    index_path = FRONTEND_DIST_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {
        "error": "Frontend build not found",
        "detail": "Build the Vite frontend or use the dedicated frontend container/dev server.",
    }


@app.get("/", tags=["Health"])
def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "healthy",
        "environment": settings.environment,
        "deployment_profile": settings.deployment_profile,
        "docs": "/docs",
        "endpoints": {
            "intel": "/api/intel/overview",
            "candidates": "/api/candidates",
            "recipes": "/api/recipes",
            "runs": "/api/runs",
            "evidence": "/api/evidence",
            "artifacts": "/api/artifacts",
            "provenance": "/api/provenance",
            "ledger": "/api/ledger",
            "disclosures": "/api/disclosures",
            "cves": "/api/cves",
            "risk": "/api/risk",
            "assets": "/api/assets",
            "feeds": "/api/feeds",
            "patches": "/api/patches",
            "templates": "/api/templates",
            "metrics": "/metrics" if settings.metrics_enabled else None
        }
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint with dependency status."""
    # Check Redis connection
    redis_healthy = check_redis_connection()

    # Determine overall status
    status = "healthy" if redis_healthy else "degraded"

    return {
        "status": status,
        "environment": settings.environment,
        "deployment_profile": settings.deployment_profile,
        "version": settings.app_version,
        "auth_enabled": settings.auth_enabled,
        "rate_limit_enabled": settings.rate_limit_enabled,
        "dependencies": {
            "database": "healthy",  # If we got here, DB is working
            "redis": "healthy" if redis_healthy else "unavailable"
        }
    }


@app.get("/api/dashboard", tags=["Dashboard"])
def get_dashboard_data():
    """
    Get aggregated dashboard data.

    Combines multiple data sources for the main dashboard view.
    """
    from app.core.database import SessionLocal
    from app.core.tenancy import get_or_create_demo_tenant
    from app.services.graph_service import ExposureGraphService
    from app.services.governance_service import GovernanceService
    from app.services.model_trust_service import ModelTrustService
    from app.services.cve_service import CVEService
    from app.services.asset_service import AssetService
    from app.services.risk_aggregator import RiskAggregator
    from app.services.workbench_service import WorkbenchService

    session = SessionLocal()
    try:
        tenant = get_or_create_demo_tenant(session)
        cve_service = CVEService(session)
        asset_service = AssetService(session)
        risk_aggregator = RiskAggregator(session)
        workbench_service = WorkbenchService(session)
        graph_service = ExposureGraphService(session)
        model_trust_service = ModelTrustService(session)
        governance_service = GovernanceService(session)

        return {
            "tenant": {"id": tenant.id, "slug": tenant.slug, "name": tenant.name},
            "risk_summary": risk_aggregator.get_risk_summary(),
            "workbench": workbench_service.get_summary(tenant, limit=6),
            "top_priorities": workbench_service.get_summary(tenant, limit=10)["actions"],
            "cve_statistics": cve_service.get_cve_statistics(),
            "trending_cves": cve_service.get_trending_cves(limit=5),
            "attack_paths": graph_service.get_attack_paths(tenant, limit=3)["paths"],
            "intel_summary": {
                "kev_entries": session.query(KEVEntry).count(),
                "epss_snapshots": session.query(EPSSSnapshot).count(),
                "attack_techniques": session.query(AttackTechnique).count(),
                "knowledge_documents": session.query(KnowledgeDocument).count(),
                "knowledge_chunks": session.query(KnowledgeChunk).count(),
                "graph_nodes": session.query(ExposureGraphNode).filter(ExposureGraphNode.tenant_id == tenant.id).count(),
                "graph_edges": session.query(ExposureGraphEdge).filter(ExposureGraphEdge.tenant_id == tenant.id).count(),
            },
            "showcase_highlights": [
                "Fuses vulnerability records with KEV, EPSS, ATT&CK, advisory knowledge, and tenant-specific exposure context.",
                "Ranks remediation actions using exploit likelihood, public exposure, crown-jewel impact, path reachability, and operational patch cost.",
                "Keeps recommendations explainable with evidence, citations, approval state, and analyst feedback instead of opaque AI-only scoring.",
            ],
            "organization_summary": asset_service.get_organization_risk_summary(tenant_id=tenant.id),
            "model_trust": model_trust_service.get_trust_snapshot(),
            "governance": {
                "approvals": governance_service.list_approvals(tenant, limit=5)["items"],
                "feedback": governance_service.list_feedback(tenant, limit=5)["items"],
            },
        }
    finally:
        session.close()


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler."""
    # Include request ID in error response if available
    request_id = getattr(request.state, 'request_id', None)
    content = {
        "error": exc.detail,
        "status_code": exc.status_code
    }
    if request_id:
        content["request_id"] = request_id

    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers=getattr(exc, 'headers', None)
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler for unexpected errors."""
    request_id = getattr(request.state, 'request_id', None)
    logger.exception(f"Unhandled exception (request_id={request_id}): {exc}")

    # Don't expose internal errors in production
    if settings.environment == "production":
        content = {"error": "Internal server error", "status_code": 500}
        if request_id:
            content["request_id"] = request_id
        return JSONResponse(status_code=500, content=content)

    content = {
        "error": str(exc),
        "type": type(exc).__name__,
        "status_code": 500
    }
    if request_id:
        content["request_id"] = request_id

    return JSONResponse(status_code=500, content=content)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )
