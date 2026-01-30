"""Application configuration settings."""

from functools import lru_cache
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "CVE Threat Radar"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    secret_key: str = "change-me-in-production"
    
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
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
