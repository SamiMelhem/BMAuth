"""Main FastAPI application for the biometric authentication system."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import close_db, init_db


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Handles startup and shutdown events for the FastAPI application.
    """
    # Startup
    logger.info("Starting biometric authentication system...")

    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

    finally:
        # Shutdown
        logger.info("Shutting down biometric authentication system...")
        await close_db()
        logger.info("Database connections closed")


# Create FastAPI application
app = FastAPI(
    title="Biometric Authentication System",
    description="Secure biometric authentication using WebAuthn/FIDO2 standards",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=settings.allowed_methods,
    allow_headers=settings.allowed_headers,
)

# Rate limiting error handler
app.state.limiter = None  # Will be initialized in security middleware
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    if settings.debug:
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "error": str(exc),
                "type": type(exc).__name__,
            }
        )

    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "biometric-auth-system",
        "version": "1.0.0",
        "environment": settings.environment,
    }


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict:
    """Root endpoint with API information."""
    return {
        "message": "Biometric Authentication System",
        "description": "Secure biometric authentication using WebAuthn/FIDO2",
        "version": "1.0.0",
        "docs_url": "/docs" if settings.debug else "Documentation disabled in production",
        "health_url": "/health",
    }


# Include routers
from app.api.v1.router import api_router
app.include_router(api_router, prefix="/api/v1")