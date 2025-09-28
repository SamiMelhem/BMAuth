"""
BMAuth - Main authentication class for FastAPI integration.

This module provides the main BMAuth class that developers will use to integrate
biometric authentication into their FastAPI applications.
"""

from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
import logging

from .config import BMAuthConfig
from .middleware import BMAuthMiddleware
from ..database.partitioning import DatabasePartitionManager
from ..cache.manager import CacheManager, start_cache_manager
from ..dashboard.api import create_dashboard_router
from ..dashboard.websocket import ConnectionManager
from ..tasks.scheduler import BackgroundTaskScheduler
from ..config.scaling import get_scaling_config
from ..cache.performance import start_performance_monitor
from ..security.models import Base

logger = logging.getLogger(__name__)


class BMAuth:
    """
    Main BMAuth class for integrating biometric authentication into FastAPI applications.

    This class provides a simple interface for developers to add complete biometric
    authentication capabilities to their FastAPI apps with minimal configuration.

    Example:
        ```python
        from fastapi import FastAPI
        from bmauth import BMAuth, BMAuthConfig

        app = FastAPI()

        # Initialize BMAuth with default configuration
        auth = BMAuth(app)

        # Or with custom configuration
        config = BMAuthConfig(
            database_url="postgresql+asyncpg://user:pass@localhost/db",
            secret_key="your-secret-key"
        )
        auth = BMAuth(app, config=config)

        # Start the authentication system
        await auth.initialize()
        ```
    """

    def __init__(
        self,
        app: Optional[FastAPI] = None,
        config: Optional[BMAuthConfig] = None,
        auto_initialize: bool = True
    ):
        """
        Initialize BMAuth instance.

        Args:
            app: FastAPI application instance
            config: BMAuth configuration (uses defaults if not provided)
            auto_initialize: Whether to automatically initialize on startup
        """
        self.app = app
        self.config = config or BMAuthConfig()
        self.scaling_config = get_scaling_config()

        # Core components
        self.engine: Optional[Any] = None
        self.session_maker: Optional[Any] = None
        self.cache_manager: Optional[CacheManager] = None
        self.connection_manager: Optional[ConnectionManager] = None
        self.task_scheduler: Optional[BackgroundTaskScheduler] = None
        self.partition_manager: Optional[DatabasePartitionManager] = None

        # State
        self._initialized = False

        if app and auto_initialize:
            self.init_app(app)

    def init_app(self, app: FastAPI) -> None:
        """
        Initialize BMAuth with a FastAPI application.

        Args:
            app: FastAPI application instance
        """
        self.app = app

        # Add middleware
        middleware = BMAuthMiddleware(self.config)
        app.add_middleware(type(middleware), **middleware.get_kwargs())

        # Add startup and shutdown events
        @app.on_event("startup")
        async def startup():
            if not self._initialized:
                await self.initialize()

        @app.on_event("shutdown")
        async def shutdown():
            await self.cleanup()

        # Add routes
        if self.config.enable_dashboard:
            dashboard_router = create_dashboard_router()
            app.include_router(dashboard_router, prefix="/bmauth")

        logger.info("BMAuth initialized with FastAPI application")

    async def initialize(self) -> None:
        """
        Initialize all BMAuth components.

        This method sets up the database, cache, dashboard, and background tasks.
        Call this during application startup.
        """
        if self._initialized:
            logger.warning("BMAuth already initialized")
            return

        try:
            logger.info("Initializing BMAuth components...")

            # Initialize database
            await self._initialize_database()

            # Initialize cache system
            await self._initialize_cache()

            # Initialize performance monitoring
            await self._initialize_performance_monitoring()

            # Initialize dashboard WebSocket manager
            if self.config.enable_dashboard:
                self.connection_manager = ConnectionManager()

            # Initialize background tasks
            await self._initialize_background_tasks()

            # Initialize database partitioning
            await self._initialize_partitioning()

            self._initialized = True
            logger.info("BMAuth initialization completed successfully")

        except Exception as e:
            logger.error(f"BMAuth initialization failed: {e}")
            raise

    async def cleanup(self) -> None:
        """
        Clean up BMAuth resources.

        Call this during application shutdown.
        """
        if not self._initialized:
            return

        try:
            logger.info("Cleaning up BMAuth components...")

            # Stop background tasks
            if self.task_scheduler:
                await self.task_scheduler.stop()

            # Stop cache manager
            if self.cache_manager:
                await self.cache_manager.stop()

            # Stop performance monitoring
            from ..cache.performance import stop_performance_monitor
            await stop_performance_monitor()

            # Close database connections
            if self.engine:
                await self.engine.dispose()

            self._initialized = False
            logger.info("BMAuth cleanup completed")

        except Exception as e:
            logger.error(f"BMAuth cleanup failed: {e}")

    async def _initialize_database(self) -> None:
        """Initialize database connection and create tables."""
        self.engine = create_async_engine(
            self.config.database_url,
            pool_size=self.scaling_config.get_database_config()["pool_size"],
            max_overflow=self.scaling_config.get_database_config()["max_overflow"],
            echo=self.config.debug
        )

        self.session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        # Create tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database initialized successfully")

    async def _initialize_cache(self) -> None:
        """Initialize cache system."""
        from ..cache.manager import start_cache_manager
        await start_cache_manager()
        self.cache_manager = self.cache_manager or CacheManager()
        logger.info("Cache system initialized")

    async def _initialize_performance_monitoring(self) -> None:
        """Initialize performance monitoring."""
        await start_performance_monitor()
        logger.info("Performance monitoring initialized")

    async def _initialize_background_tasks(self) -> None:
        """Initialize background task scheduler."""
        self.task_scheduler = BackgroundTaskScheduler(
            session_maker=self.session_maker,
            scaling_config=self.scaling_config
        )
        await self.task_scheduler.start()
        logger.info("Background task scheduler initialized")

    async def _initialize_partitioning(self) -> None:
        """Initialize database partitioning."""
        if self.session_maker:
            async with self.session_maker() as session:
                self.partition_manager = DatabasePartitionManager(session)
                await self.partition_manager.initialize()
        logger.info("Database partitioning initialized")

    def get_session_dependency(self):
        """
        FastAPI dependency for getting database sessions.

        Returns:
            Dependency function for FastAPI routes

        Example:
            ```python
            @app.get("/users/me")
            async def get_current_user(
                session: AsyncSession = Depends(auth.get_session_dependency())
            ):
                # Use session for database operations
                pass
            ```
        """
        async def get_session() -> AsyncSession:
            if not self.session_maker:
                raise HTTPException(
                    status_code=500,
                    detail="BMAuth not properly initialized"
                )

            async with self.session_maker() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise
                finally:
                    await session.close()

        return get_session

    def get_cache_dependency(self):
        """
        FastAPI dependency for getting cache manager.

        Returns:
            Dependency function for FastAPI routes
        """
        def get_cache() -> CacheManager:
            if not self.cache_manager:
                raise HTTPException(
                    status_code=500,
                    detail="Cache system not available"
                )
            return self.cache_manager

        return get_cache

    @property
    def is_initialized(self) -> bool:
        """Check if BMAuth is fully initialized."""
        return self._initialized

    def get_stats(self) -> Dict[str, Any]:
        """
        Get BMAuth system statistics.

        Returns:
            Dictionary with system statistics
        """
        stats = {
            "initialized": self._initialized,
            "config": {
                "debug": self.config.debug,
                "enable_dashboard": self.config.enable_dashboard,
                "scaling_level": self.scaling_config.scaling_level.value
            }
        }

        if self.cache_manager:
            stats["cache"] = self.cache_manager.get_stats()

        if self.connection_manager:
            stats["websocket_connections"] = len(self.connection_manager.active_connections)

        return stats