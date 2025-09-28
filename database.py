"""Database configuration and session management with auto-scaling optimization."""

import logging
from typing import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)

# Create declarative base for models
Base = declarative_base()

# Get database configuration with auto-scaling settings
db_config = settings.get_database_config()

# Create async engine for database operations with auto-scaling configuration
async_engine = create_async_engine(
    db_config["url"],
    echo=settings.debug,
    future=True,
    pool_pre_ping=db_config.get("pool_pre_ping", True),
    pool_size=db_config.get("pool_size", 5),
    max_overflow=db_config.get("max_overflow", 10),
    pool_recycle=db_config.get("pool_recycle", 3600),
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Sync engine for Alembic migrations
sync_engine = create_engine(
    settings.database_url,
    echo=settings.debug,
    future=True,
    pool_pre_ping=True,
)

# Sync session factory for migrations
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency function to get database session.

    Yields:
        AsyncSession: Database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables and optimization features."""
    async with async_engine.begin() as conn:
        # Import all models to ensure they are registered
        from app.models import user, webauthn_credential, security_log, webauthn_challenge  # noqa: F401

        # Create all tables
        await conn.run_sync(Base.metadata.create_all)

    # Initialize database optimization if enabled
    if settings.scaling_config.enable_partitioning:
        from app.database.partitioning import initialize_database_optimization

        async with AsyncSessionLocal() as session:
            try:
                await initialize_database_optimization(session)
                logger.info("Database optimization initialized")
            except Exception as e:
                logger.warning(f"Could not initialize database optimization: {e}")
                # Don't fail startup if optimization fails


async def close_db() -> None:
    """Close database connections."""
    await async_engine.dispose()