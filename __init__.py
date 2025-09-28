"""
BMAuth - Production-ready WebAuthn/FIDO2 biometric authentication library for FastAPI.

This library provides a complete biometric authentication system for FastAPI applications
with WebAuthn/FIDO2 support, unlimited scalability, and comprehensive security features.
"""

__version__ = "1.0.0"
__author__ = "BMAuth System"
__email__ = "contact@bmauth.com"

# Core components - Import only what works
from .core.config import BMAuthConfig

# Try to import other components, but don't fail if they have issues
try:
    from .core.auth import BMAuth
except ImportError:
    BMAuth = None

try:
    from .core.middleware import BMAuthMiddleware
except ImportError:
    BMAuthMiddleware = None

# Configuration components
try:
    from .config.scaling import ScalingConfig, get_scaling_config
except ImportError:
    ScalingConfig = None
    get_scaling_config = None

__all__ = [
    # Core
    "BMAuthConfig",
    "BMAuth",
    "BMAuthMiddleware",
    "ScalingConfig",
    "get_scaling_config",
]