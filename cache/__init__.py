"""
Intelligent caching and performance management module.

This module provides multi-tier caching, automatic memory management,
and performance optimization for scalable authentication systems.
"""

from .manager import CacheManager, get_cache_manager
from .backends import MemoryCache, RedisCache, DiskCache
from .decorators import cached, cache_result, invalidate_cache
from .performance import PerformanceMonitor, get_performance_monitor

__all__ = [
    "CacheManager",
    "get_cache_manager",
    "MemoryCache",
    "RedisCache",
    "DiskCache",
    "cached",
    "cache_result",
    "invalidate_cache",
    "PerformanceMonitor",
    "get_performance_monitor",
]