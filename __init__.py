"""
BMAuth - Production-ready WebAuthn/FIDO2 biometric authentication library for FastAPI.

This library provides a complete biometric authentication system for FastAPI applications
with WebAuthn/FIDO2 support, unlimited scalability, and comprehensive security features.
"""

__version__ = "1.0.0"
__author__ = "BMAuth System"
__email__ = "contact@bmauth.com"

# Core components
from .core.auth import BMAuth
from .core.config import BMAuthConfig
from .core.middleware import BMAuthMiddleware

# Security components
from .security.models import User, Device, AuthEvent
from .security.auth import authenticate_user, register_device
from .security.rate_limiting import RateLimiter

# Dashboard components
from .dashboard.api import create_dashboard_router
from .dashboard.websocket import ConnectionManager

# Cache components
from .cache.manager import CacheManager, start_cache_manager
from .cache.decorators import cached, cache_result, CacheService

# Database components
from .database.partitioning import DatabasePartitionManager
from .database.models import Base

# Configuration components
from .config.scaling import ScalingConfig, get_scaling_config

# Task components
from .tasks.scheduler import BackgroundTaskScheduler

__all__ = [
    # Core
    "BMAuth",
    "BMAuthConfig",
    "BMAuthMiddleware",
    # Security
    "User",
    "Device",
    "AuthEvent",
    "authenticate_user",
    "register_device",
    "RateLimiter",
    # Dashboard
    "create_dashboard_router",
    "ConnectionManager",
    # Cache
    "CacheManager",
    "start_cache_manager",
    "cached",
    "cache_result",
    "CacheService",
    # Database
    "DatabasePartitionManager",
    "Base",
    # Configuration
    "ScalingConfig",
    "get_scaling_config",
    # Tasks
    "BackgroundTaskScheduler",
]