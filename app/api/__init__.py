"""API routes."""

from app.api.routes import asset_routes, cve_routes, feed_routes, risk_routes

__all__ = ["cve_routes", "risk_routes", "asset_routes", "feed_routes"]
