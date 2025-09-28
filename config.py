"""Application configuration settings with auto-scaling capabilities."""

import secrets
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings

from .config.scaling import get_scaling_config, ScalingConfig


class Settings(BaseSettings):
    """Application settings with validation and defaults."""

    # Database Configuration
    database_url: str = Field(
        default="sqlite:///./biometric_auth.db",
        description="Database connection URL"
    )

    # Redis Configuration
    redis_url: Optional[str] = Field(
        default=None,
        description="Redis connection URL (optional)"
    )

    # Security Configuration
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Secret key for JWT tokens"
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=60, description="Access token expiration time"
    )

    # WebAuthn Configuration
    rp_id: str = Field(default="localhost", description="Relying Party ID")
    rp_name: str = Field(
        default="Biometric Auth System", description="Relying Party Name"
    )
    origin: str = Field(
        default="http://localhost:3000", description="Application origin URL"
    )

    # Environment Configuration
    environment: str = Field(default="development", description="Environment name")
    debug: bool = Field(default=True, description="Debug mode")

    # CORS Configuration
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    allowed_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE"],
        description="Allowed HTTP methods"
    )
    allowed_headers: List[str] = Field(
        default=["*"], description="Allowed headers"
    )

    # Rate Limiting (auto-configured based on scale)
    rate_limit_requests: Optional[int] = Field(
        default=None, description="Rate limit requests per window (auto-configured if None)"
    )
    rate_limit_window: int = Field(
        default=60, description="Rate limit window in seconds"
    )

    # Security Headers
    enable_csp: bool = Field(default=True, description="Enable CSP headers")
    enable_hsts: bool = Field(default=True, description="Enable HSTS headers")

    # Logging Configuration
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format")

    @validator("environment")
    def validate_environment(cls, v: str) -> str:
        """Validate environment value."""
        allowed = ["development", "staging", "production"]
        if v.lower() not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v.lower()

    @validator("log_level")
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of: {allowed}")
        return v.upper()

    @validator("origin")
    def validate_origin(cls, v: str) -> str:
        """Validate origin URL format."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("Origin must start with http:// or https://")
        return v.rstrip("/")

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"

    @property
    def database_url_async(self) -> str:
        """Get async database URL for SQLite."""
        if self.database_url.startswith("sqlite"):
            return self.database_url.replace("sqlite:///", "sqlite+aiosqlite:///")
        return self.database_url

    @property
    def scaling_config(self) -> ScalingConfig:
        """Get auto-scaling configuration."""
        return get_scaling_config()

    def get_rate_limit_per_minute(self) -> int:
        """Get rate limit per minute (auto-configured if not set)."""
        if self.rate_limit_requests is not None:
            return self.rate_limit_requests
        return self.scaling_config.rate_limit_per_minute

    def get_database_config(self) -> dict:
        """Get database configuration with connection pooling."""
        base_config = {
            "url": self.database_url_async,
            **self.scaling_config.get_database_url_config()
        }
        return base_config

    def get_session_config(self) -> dict:
        """Get session management configuration."""
        return {
            "max_concurrent": self.scaling_config.max_concurrent_sessions,
            "timeout_minutes": self.scaling_config.session_timeout_minutes,
            "cleanup_interval": self.scaling_config.session_cleanup_interval
        }

    def get_security_config(self) -> dict:
        """Get security configuration."""
        config = self.scaling_config.get_security_config()
        config.update({
            "secret_key": self.secret_key,
            "algorithm": self.algorithm,
            "access_token_expire_minutes": self.access_token_expire_minutes
        })
        return config

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()