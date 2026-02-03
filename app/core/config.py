"""
Application configuration settings.

Author: Archishman Paul

Configuration management done right. All settings are loaded from
environment variables with sensible defaults for development.

The 12-factor app methodology recommends separating config from code.
This module follows that principle - no hardcoded secrets, no
environment-specific logic scattered across the codebase.

Security Enhancement: Added authentication, CORS, and rate limiting settings.
"""

import secrets
from functools import lru_cache
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "CVE Threat Radar"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False  # Changed default to False for security

    # Security - Secret Key
    # In production, this MUST be set via environment variable
    secret_key: str = ""

    # JWT Authentication Settings
    auth_enabled: bool = False  # Set to True in production
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS Settings
    # In production, set specific origins via ALLOWED_ORIGINS env var (comma-separated)
    allowed_origins: str = "http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:8000"

    @property
    def cors_origins(self) -> List[str]:
        """Parse allowed origins from comma-separated string."""
        if not self.allowed_origins:
            return []
        return [origin.strip() for origin in self.allowed_origins.split(',') if origin.strip()]

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    rate_limit_requests_per_hour: int = 2000
    rate_limit_burst: int = 20

    # Database (SQLite for local dev, PostgreSQL for production)
    database_url: str = "sqlite:///./cve_threat_radar.db"
    async_database_url: str = "sqlite+aiosqlite:///./cve_threat_radar.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # External APIs
    nvd_api_key: Optional[str] = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    exploit_db_url: str = "https://www.exploit-db.com"

    # ML Settings
    model_path: str = "./models"
    prediction_threshold: float = 0.5

    # Scheduler
    feed_update_interval_hours: int = 6
    feed_scheduler_enabled: bool = True
    feed_scheduler_max_instances: int = 1

    # Metrics endpoint protection
    metrics_enabled: bool = True
    metrics_require_auth: bool = False  # Set to True in production

    @field_validator('secret_key', mode='before')
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        """Validate and generate secret key if needed."""
        # Get environment from the values being validated
        # Note: In Pydantic v2, we can't easily access other fields during validation
        # So we generate a random key for development if not set
        if not v or v == "change-me-in-production":
            # Generate a secure random key for development
            # In production, this should be set via environment variable
            return secrets.token_urlsafe(32)
        return v

    def validate_production_settings(self) -> List[str]:
        """
        Validate settings for production environment.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if self.environment == "production":
            if self.debug:
                errors.append("Debug mode must be disabled in production")

            if not self.secret_key or len(self.secret_key) < 32:
                errors.append("SECRET_KEY must be at least 32 characters in production")

            if "*" in self.cors_origins:
                errors.append("CORS allowed_origins cannot be '*' in production")

            if not self.auth_enabled:
                errors.append("Authentication should be enabled in production")

            if "sqlite" in self.database_url.lower():
                errors.append("SQLite should not be used in production")

        return errors

    class Config:
        env_file = ".env"
        case_sensitive = False
        # Allow extra fields from environment
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Module-level settings instance
settings = get_settings()


def validate_settings_for_startup() -> None:
    """
    Validate settings at application startup.

    Raises:
        ValueError: If critical settings are invalid for the environment
    """
    errors = settings.validate_production_settings()

    if errors and settings.environment == "production":
        error_msg = "Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ValueError(error_msg)
