"""
Auto-scaling configuration system for biometric authentication library.

This module automatically detects system resources and configures optimal
settings for any scale from single-user applications to enterprise deployments.
"""

import os
import psutil
import platform
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class ScaleLevel(Enum):
    """Automatic scale detection levels."""
    SMALL = "small"      # < 1K users
    MEDIUM = "medium"    # 1K - 100K users
    LARGE = "large"      # 100K - 1M users
    ENTERPRISE = "enterprise"  # 1M - 10M users
    HYPERSCALE = "hyperscale"  # 10M+ users


@dataclass
class SystemResources:
    """Detected system resources."""
    cpu_cores: int
    total_memory_gb: float
    available_memory_gb: float
    disk_space_gb: float
    platform: str
    python_version: str

    @classmethod
    def detect(cls) -> "SystemResources":
        """Automatically detect current system resources."""
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return cls(
            cpu_cores=psutil.cpu_count(logical=True),
            total_memory_gb=memory.total / (1024**3),
            available_memory_gb=memory.available / (1024**3),
            disk_space_gb=disk.free / (1024**3),
            platform=platform.system(),
            python_version=platform.python_version()
        )


@dataclass
class ScalingConfig:
    """
    Auto-scaling configuration that adapts to system resources and load.

    All values marked as "auto" will be automatically calculated based on
    detected system resources and current usage patterns.
    """

    # Session Management
    max_concurrent_sessions: Union[int, str] = "auto"
    session_cleanup_interval: Union[int, str] = "auto"
    session_timeout_minutes: Union[int, str] = "auto"

    # Data Retention
    event_retention_days: Union[int, str] = "auto"
    log_retention_days: Union[int, str] = "auto"
    cleanup_batch_size: Union[int, str] = "auto"

    # Dashboard Settings
    dashboard_page_size: Union[int, str] = "auto"
    real_time_update_interval: Union[int, str] = "auto"
    max_websocket_connections: Union[int, str] = "auto"
    dashboard_cache_ttl: Union[int, str] = "auto"

    # Database Configuration
    db_connection_pool_size: Union[int, str] = "auto"
    db_max_overflow: Union[int, str] = "auto"
    enable_partitioning: Union[bool, str] = "auto"
    partition_interval: Union[str, str] = "auto"  # 'monthly', 'weekly', 'daily'

    # Performance Settings
    background_task_batch_size: Union[int, str] = "auto"
    risk_score_cache_ttl: Union[int, str] = "auto"
    enable_query_cache: Union[bool, str] = "auto"
    cache_max_memory_mb: Union[int, str] = "auto"

    # Security Settings
    rate_limit_per_minute: Union[int, str] = "auto"
    max_failed_attempts: Union[int, str] = "auto"
    lockout_duration_minutes: Union[int, str] = "auto"

    # Enterprise Features
    enable_sharding: bool = False
    enable_read_replicas: bool = False
    max_instances: Union[int, str] = "auto"
    enable_geographic_distribution: bool = False

    # Manual Overrides
    force_scale_level: Optional[ScaleLevel] = None
    custom_settings: Dict[str, Any] = field(default_factory=dict)

    # System Resources (detected automatically)
    _system_resources: Optional[SystemResources] = field(default=None, init=False)
    _detected_scale: Optional[ScaleLevel] = field(default=None, init=False)

    def __post_init__(self):
        """Initialize auto-detection after creation."""
        self._system_resources = SystemResources.detect()
        self._detected_scale = self._detect_scale_level()
        self._apply_auto_settings()

    def _detect_scale_level(self) -> ScaleLevel:
        """Automatically detect appropriate scale level based on system resources."""
        if self.force_scale_level:
            return self.force_scale_level

        resources = self._system_resources

        # Scale detection based on system capabilities
        if resources.total_memory_gb >= 64 and resources.cpu_cores >= 16:
            return ScaleLevel.HYPERSCALE
        elif resources.total_memory_gb >= 32 and resources.cpu_cores >= 8:
            return ScaleLevel.ENTERPRISE
        elif resources.total_memory_gb >= 16 and resources.cpu_cores >= 4:
            return ScaleLevel.LARGE
        elif resources.total_memory_gb >= 8 and resources.cpu_cores >= 2:
            return ScaleLevel.MEDIUM
        else:
            return ScaleLevel.SMALL

    def _apply_auto_settings(self):
        """Apply automatic settings based on detected scale level."""
        scale = self._detected_scale
        resources = self._system_resources

        # Apply scale-specific settings
        if scale == ScaleLevel.SMALL:
            self._apply_small_scale_settings(resources)
        elif scale == ScaleLevel.MEDIUM:
            self._apply_medium_scale_settings(resources)
        elif scale == ScaleLevel.LARGE:
            self._apply_large_scale_settings(resources)
        elif scale == ScaleLevel.ENTERPRISE:
            self._apply_enterprise_scale_settings(resources)
        elif scale == ScaleLevel.HYPERSCALE:
            self._apply_hyperscale_settings(resources)

        # Apply custom overrides
        for key, value in self.custom_settings.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def _apply_small_scale_settings(self, resources: SystemResources):
        """Settings for small deployments (< 1K users)."""
        self.max_concurrent_sessions = min(1000, int(resources.available_memory_gb * 100))
        self.session_cleanup_interval = 3600  # 1 hour
        self.session_timeout_minutes = 60

        self.event_retention_days = 90
        self.log_retention_days = 30
        self.cleanup_batch_size = 100

        self.dashboard_page_size = 50
        self.real_time_update_interval = 10
        self.max_websocket_connections = 50
        self.dashboard_cache_ttl = 300  # 5 minutes

        self.db_connection_pool_size = 5
        self.db_max_overflow = 10
        self.enable_partitioning = False
        self.partition_interval = "monthly"

        self.background_task_batch_size = 50
        self.risk_score_cache_ttl = 3600
        self.enable_query_cache = True
        self.cache_max_memory_mb = int(resources.available_memory_gb * 100)  # 10% of available memory

        self.rate_limit_per_minute = 60
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 15

        self.max_instances = 1

    def _apply_medium_scale_settings(self, resources: SystemResources):
        """Settings for medium deployments (1K - 100K users)."""
        self.max_concurrent_sessions = min(10000, int(resources.available_memory_gb * 500))
        self.session_cleanup_interval = 1800  # 30 minutes
        self.session_timeout_minutes = 120

        self.event_retention_days = 180
        self.log_retention_days = 60
        self.cleanup_batch_size = 500

        self.dashboard_page_size = 100
        self.real_time_update_interval = 5
        self.max_websocket_connections = 200
        self.dashboard_cache_ttl = 600  # 10 minutes

        self.db_connection_pool_size = 20
        self.db_max_overflow = 30
        self.enable_partitioning = True
        self.partition_interval = "monthly"

        self.background_task_batch_size = 500
        self.risk_score_cache_ttl = 1800
        self.enable_query_cache = True
        self.cache_max_memory_mb = int(resources.available_memory_gb * 200)  # 20% of available memory

        self.rate_limit_per_minute = 120
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30

        self.max_instances = resources.cpu_cores

    def _apply_large_scale_settings(self, resources: SystemResources):
        """Settings for large deployments (100K - 1M users)."""
        self.max_concurrent_sessions = min(100000, int(resources.available_memory_gb * 1000))
        self.session_cleanup_interval = 900  # 15 minutes
        self.session_timeout_minutes = 240

        self.event_retention_days = 365
        self.log_retention_days = 90
        self.cleanup_batch_size = 1000

        self.dashboard_page_size = 200
        self.real_time_update_interval = 3
        self.max_websocket_connections = 500
        self.dashboard_cache_ttl = 900  # 15 minutes

        self.db_connection_pool_size = 50
        self.db_max_overflow = 50
        self.enable_partitioning = True
        self.partition_interval = "weekly"

        self.background_task_batch_size = 1000
        self.risk_score_cache_ttl = 900
        self.enable_query_cache = True
        self.cache_max_memory_mb = int(resources.available_memory_gb * 300)  # 30% of available memory

        self.rate_limit_per_minute = 300
        self.max_failed_attempts = 3
        self.lockout_duration_minutes = 60

        self.max_instances = resources.cpu_cores * 2
        self.enable_read_replicas = True

    def _apply_enterprise_scale_settings(self, resources: SystemResources):
        """Settings for enterprise deployments (1M - 10M users)."""
        self.max_concurrent_sessions = min(1000000, int(resources.available_memory_gb * 2000))
        self.session_cleanup_interval = 300  # 5 minutes
        self.session_timeout_minutes = 480

        self.event_retention_days = 730  # 2 years
        self.log_retention_days = 180
        self.cleanup_batch_size = 5000

        self.dashboard_page_size = 500
        self.real_time_update_interval = 1
        self.max_websocket_connections = 1000
        self.dashboard_cache_ttl = 1800  # 30 minutes

        self.db_connection_pool_size = 100
        self.db_max_overflow = 100
        self.enable_partitioning = True
        self.partition_interval = "weekly"

        self.background_task_batch_size = 5000
        self.risk_score_cache_ttl = 300
        self.enable_query_cache = True
        self.cache_max_memory_mb = int(resources.available_memory_gb * 500)  # 50% of available memory

        self.rate_limit_per_minute = 600
        self.max_failed_attempts = 3
        self.lockout_duration_minutes = 120

        self.max_instances = resources.cpu_cores * 4
        self.enable_read_replicas = True
        self.enable_sharding = True

    def _apply_hyperscale_settings(self, resources: SystemResources):
        """Settings for hyperscale deployments (10M+ users)."""
        self.max_concurrent_sessions = int(resources.available_memory_gb * 5000)  # No artificial limit
        self.session_cleanup_interval = 60  # 1 minute
        self.session_timeout_minutes = 720

        self.event_retention_days = 2555  # 7 years
        self.log_retention_days = 365
        self.cleanup_batch_size = 10000

        self.dashboard_page_size = 1000
        self.real_time_update_interval = 1
        self.max_websocket_connections = 5000
        self.dashboard_cache_ttl = 3600  # 1 hour

        self.db_connection_pool_size = 200
        self.db_max_overflow = 200
        self.enable_partitioning = True
        self.partition_interval = "daily"

        self.background_task_batch_size = 10000
        self.risk_score_cache_ttl = 60
        self.enable_query_cache = True
        self.cache_max_memory_mb = int(resources.available_memory_gb * 1000)  # Up to 1GB per GB available

        self.rate_limit_per_minute = 1200
        self.max_failed_attempts = 3
        self.lockout_duration_minutes = 240

        self.max_instances = resources.cpu_cores * 8
        self.enable_read_replicas = True
        self.enable_sharding = True
        self.enable_geographic_distribution = True

    def get_database_url_config(self) -> Dict[str, Any]:
        """Get database configuration based on current settings."""
        return {
            "pool_size": self.db_connection_pool_size,
            "max_overflow": self.db_max_overflow,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
            "echo": False  # Disable in production for performance
        }

    def get_cache_config(self) -> Dict[str, Any]:
        """Get cache configuration based on current settings."""
        return {
            "enabled": self.enable_query_cache,
            "max_memory_mb": self.cache_max_memory_mb,
            "default_ttl": self.risk_score_cache_ttl,
            "dashboard_ttl": self.dashboard_cache_ttl
        }

    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance-related configuration."""
        return {
            "background_batch_size": self.background_task_batch_size,
            "cleanup_interval": self.session_cleanup_interval,
            "max_instances": self.max_instances,
            "enable_partitioning": self.enable_partitioning,
            "partition_interval": self.partition_interval
        }

    def get_security_config(self) -> Dict[str, Any]:
        """Get security-related configuration."""
        return {
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "max_failed_attempts": self.max_failed_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "session_timeout_minutes": self.session_timeout_minutes
        }

    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get dashboard-specific configuration."""
        return {
            "page_size": self.dashboard_page_size,
            "update_interval": self.real_time_update_interval,
            "max_websocket_connections": self.max_websocket_connections,
            "cache_ttl": self.dashboard_cache_ttl
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        config = {}
        for field_name in self.__dataclass_fields__:
            if not field_name.startswith('_'):
                config[field_name] = getattr(self, field_name)

        # Add computed configurations
        config.update({
            "detected_scale_level": self._detected_scale.value if self._detected_scale else None,
            "system_resources": {
                "cpu_cores": self._system_resources.cpu_cores,
                "total_memory_gb": self._system_resources.total_memory_gb,
                "available_memory_gb": self._system_resources.available_memory_gb,
                "platform": self._system_resources.platform
            } if self._system_resources else None,
            "database_config": self.get_database_url_config(),
            "cache_config": self.get_cache_config(),
            "performance_config": self.get_performance_config(),
            "security_config": self.get_security_config(),
            "dashboard_config": self.get_dashboard_config()
        })

        return config

    @classmethod
    def from_environment(cls) -> "ScalingConfig":
        """Create configuration from environment variables."""
        config = cls()

        # Override with environment variables if present
        env_mappings = {
            "MAX_CONCURRENT_SESSIONS": "max_concurrent_sessions",
            "EVENT_RETENTION_DAYS": "event_retention_days",
            "DASHBOARD_PAGE_SIZE": "dashboard_page_size",
            "DB_POOL_SIZE": "db_connection_pool_size",
            "ENABLE_PARTITIONING": "enable_partitioning",
            "FORCE_SCALE_LEVEL": "force_scale_level"
        }

        for env_var, config_attr in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Convert string values to appropriate types
                if config_attr == "force_scale_level":
                    try:
                        setattr(config, config_attr, ScaleLevel(env_value.lower()))
                    except ValueError:
                        pass  # Invalid scale level, ignore
                elif config_attr == "enable_partitioning":
                    setattr(config, config_attr, env_value.lower() in ('true', '1', 'yes'))
                else:
                    try:
                        setattr(config, config_attr, int(env_value))
                    except ValueError:
                        setattr(config, config_attr, env_value)

        # Re-apply auto settings after environment overrides
        config._apply_auto_settings()
        return config


# Global configuration instance
_global_config: Optional[ScalingConfig] = None


def get_scaling_config() -> ScalingConfig:
    """Get the global scaling configuration instance."""
    global _global_config
    if _global_config is None:
        _global_config = ScalingConfig.from_environment()
    return _global_config


def set_scaling_config(config: ScalingConfig):
    """Set a custom scaling configuration."""
    global _global_config
    _global_config = config


def reset_scaling_config():
    """Reset to auto-detected configuration."""
    global _global_config
    _global_config = None


# Convenience functions for common configurations
def configure_for_development() -> ScalingConfig:
    """Get configuration optimized for development environments."""
    config = ScalingConfig()
    config.force_scale_level = ScaleLevel.SMALL
    config.custom_settings = {
        "event_retention_days": 7,
        "log_retention_days": 3,
        "real_time_update_interval": 5,
        "enable_partitioning": False
    }
    config._apply_auto_settings()
    return config


def configure_for_production(scale_level: Optional[ScaleLevel] = None) -> ScalingConfig:
    """Get configuration optimized for production environments."""
    config = ScalingConfig()
    if scale_level:
        config.force_scale_level = scale_level
    config.custom_settings = {
        "enable_query_cache": True,
        "enable_partitioning": True,
        "max_failed_attempts": 3,
        "lockout_duration_minutes": 60
    }
    config._apply_auto_settings()
    return config


def configure_for_enterprise() -> ScalingConfig:
    """Get configuration optimized for enterprise deployments."""
    config = ScalingConfig()
    config.force_scale_level = ScaleLevel.ENTERPRISE
    config.custom_settings = {
        "event_retention_days": 2555,  # 7 years for compliance
        "enable_sharding": True,
        "enable_read_replicas": True,
        "enable_geographic_distribution": True
    }
    config._apply_auto_settings()
    return config