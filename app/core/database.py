"""Database connection and session management."""

import logging
import time
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.pool import StaticPool

from app.core.config import settings

logger = logging.getLogger(__name__)

# Check if using SQLite
is_sqlite = "sqlite" in settings.database_url


def create_engine_with_retry(
    url: str,
    max_retries: int = 5,
    retry_delay: float = 2.0,
    **engine_kwargs
):
    """
    Create database engine with retry logic for production reliability.

    Args:
        url: Database connection URL
        max_retries: Maximum number of connection attempts
        retry_delay: Initial delay between retries (exponential backoff)
        **engine_kwargs: Additional arguments passed to create_engine

    Returns:
        SQLAlchemy engine instance
    """
    engine = create_engine(url, **engine_kwargs)

    # For SQLite, no need to test connection
    if "sqlite" in url:
        return engine

    # Test connection with retries for PostgreSQL
    for attempt in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection established successfully")
            return engine
        except OperationalError as e:
            if attempt < max_retries - 1:
                wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(
                    f"Database connection attempt {attempt + 1}/{max_retries} failed. "
                    f"Retrying in {wait_time:.1f}s... Error: {e}"
                )
                time.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to database after {max_retries} attempts")
                raise

    return engine


# Sync engine for migrations and scripts
if is_sqlite:
    sqlite_engine_kwargs = {"connect_args": {"check_same_thread": False}}
    if settings.database_url in {"sqlite://", "sqlite:///:memory:"}:
        sqlite_engine_kwargs["poolclass"] = StaticPool
    engine = create_engine(settings.database_url, **sqlite_engine_kwargs)
else:
    engine = create_engine_with_retry(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

# Async engine for API requests (skip for SQLite simplicity)
async_engine = None
if not is_sqlite:
    async_engine = create_async_engine(
        settings.async_database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

# Session factories
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Base class for models
Base = declarative_base()


async def get_async_session() -> AsyncSession:
    """Dependency for getting async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_session() -> Generator[Session, None, None]:
    """Get synchronous database session."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
