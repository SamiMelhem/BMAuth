"""
BMAuth configuration management.

This module provides configuration classes for BMAuth with sensible defaults
and environment variable support.
"""

from typing import Optional, List, Dict, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
import os


class BMAuthConfig(BaseSettings):
    """
    BMAuth configuration with environment variable support.

    All configuration values can be set via environment variables with the
    BMAUTH_ prefix (e.g., BMAUTH_DATABASE_URL).

    Example:
        ```python
        # Use environment variables
        os.environ["BMAUTH_DATABASE_URL"] = "postgresql+asyncpg://..."
        os.environ["BMAUTH_SECRET_KEY"] = "your-secret-key"
        config = BMAuthConfig()

        # Or set directly
        config = BMAuthConfig(
            database_url="postgresql+asyncpg://user:pass@localhost/db",
            secret_key="your-secret-key"
        )
        ```
    """

    # Database configuration
    database_url: str = Field(
        default="sqlite+aiosqlite:///./bmauth.db",
        description="Database URL for SQLAlchemy"
    )

    # Security configuration
    secret_key: str = Field(
        default="change-this-in-production",
        description="Secret key for JWT tokens and encryption"
    )

    algorithm: str = Field(
        default="HS256",
        description="Algorithm for JWT token signing"
    )

    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration time in minutes"
    )

    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration time in days"
    )

    # WebAuthn configuration
    rp_id: str = Field(
        default="localhost",
        description="Relying Party ID for WebAuthn"
    )

    rp_name: str = Field(
        default="BMAuth Application",
        description="Relying Party name for WebAuthn"
    )

    rp_origins: List[str] = Field(
        default=["http://localhost:8000", "https://localhost:8000"],
        description="Allowed origins for WebAuthn"
    )

    # Rate limiting configuration
    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable rate limiting for authentication endpoints"
    )

    rate_limit_requests: int = Field(
        default=5,
        description="Maximum requests per rate limit window"
    )

    rate_limit_window: int = Field(
        default=60,
        description="Rate limit window in seconds"
    )

    # Cache configuration
    enable_caching: bool = Field(
        default=True,
        description="Enable caching system"
    )

    redis_url: Optional[str] = Field(
        default=None,
        description="Redis URL for caching (optional)"
    )

    cache_ttl_default: int = Field(
        default=3600,
        description="Default cache TTL in seconds"
    )

    # Dashboard configuration
    enable_dashboard: bool = Field(
        default=True,
        description="Enable BMAuth dashboard"
    )

    dashboard_username: str = Field(
        default="admin",
        description="Dashboard admin username"
    )

    dashboard_password: str = Field(
        default="change-this-password",
        description="Dashboard admin password"
    )

    # Logging configuration
    debug: bool = Field(
        default=False,
        description="Enable debug logging"
    )

    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )

    # Performance configuration
    enable_performance_monitoring: bool = Field(
        default=True,
        description="Enable performance monitoring"
    )

    max_concurrent_sessions: Optional[int] = Field(
        default=None,
        description="Maximum concurrent user sessions (auto-detected if None)"
    )

    # Background tasks configuration
    enable_background_tasks: bool = Field(
        default=True,
        description="Enable background maintenance tasks"
    )

    cleanup_interval_hours: int = Field(
        default=24,
        description="Interval for cleanup tasks in hours"
    )

    # Database partitioning configuration
    enable_partitioning: bool = Field(
        default=True,
        description="Enable database partitioning for scalability"
    )

    partition_retention_days: int = Field(
        default=90,
        description="How long to keep old partitions in days"
    )

    @field_validator("secret_key")
    def validate_secret_key(cls, v):
        if v == "change-this-in-production":
            if os.getenv("BMAUTH_ENV", "development") == "production":
                raise ValueError("Secret key must be changed in production")
        return v

    @field_validator("dashboard_password")
    def validate_dashboard_password(cls, v):
        if v == "change-this-password":
            if os.getenv("BMAUTH_ENV", "development") == "production":
                raise ValueError("Dashboard password must be changed in production")
        return v

    @field_validator("rp_origins")
    def validate_origins(cls, v):
        if not v:
            raise ValueError("At least one origin must be specified")
        return v

    def get_database_config(self) -> Dict[str, Any]:
        """Get database-specific configuration."""
        return {
            "url": self.database_url,
            "echo": self.debug
        }

    def get_webauthn_config(self) -> Dict[str, Any]:
        """Get WebAuthn-specific configuration."""
        return {
            "rp_id": self.rp_id,
            "rp_name": self.rp_name,
            "rp_origins": self.rp_origins
        }

    def get_cache_config(self) -> Dict[str, Any]:
        """Get cache-specific configuration."""
        return {
            "enabled": self.enable_caching,
            "redis_url": self.redis_url,
            "default_ttl": self.cache_ttl_default
        }

    def get_security_config(self) -> Dict[str, Any]:
        """Get security-specific configuration."""
        return {
            "secret_key": self.secret_key,
            "algorithm": self.algorithm,
            "access_token_expire_minutes": self.access_token_expire_minutes,
            "refresh_token_expire_days": self.refresh_token_expire_days
        }

    def get_rate_limit_config(self) -> Dict[str, Any]:
        """Get rate limiting configuration."""
        return {
            "enabled": self.enable_rate_limiting,
            "requests": self.rate_limit_requests,
            "window": self.rate_limit_window
        }

    class Config:
        env_prefix = "BMAUTH_"
        env_file = ".env"
        case_sensitive = False