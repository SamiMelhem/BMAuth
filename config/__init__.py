"""
Configuration module for biometric authentication library.

This module provides auto-scaling configuration that adapts to system
resources and deployment requirements.
"""

from .scaling import (
    ScalingConfig,
    ScaleLevel,
    SystemResources,
    get_scaling_config,
    set_scaling_config,
    reset_scaling_config,
    configure_for_development,
    configure_for_production,
    configure_for_enterprise,
)

__all__ = [
    "ScalingConfig",
    "ScaleLevel",
    "SystemResources",
    "get_scaling_config",
    "set_scaling_config",
    "reset_scaling_config",
    "configure_for_development",
    "configure_for_production",
    "configure_for_enterprise",
]