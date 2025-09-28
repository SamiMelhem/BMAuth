"""
Intelligent cache manager with multi-tier caching and automatic optimization.

This module provides a unified cache interface with automatic backend selection,
cache warming, and intelligent invalidation strategies.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Union, Callable
from enum import Enum
import hashlib
import json

from app.config.scaling import get_scaling_config
from .backends import CacheBackend, MemoryCache, RedisCache, DiskCache

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Cache strategy options."""
    MEMORY_ONLY = "memory_only"
    REDIS_ONLY = "redis_only"
    DISK_ONLY = "disk_only"
    TIERED = "tiered"  # Memory -> Redis -> Disk
    WRITE_THROUGH = "write_through"  # Write to all backends
    WRITE_BEHIND = "write_behind"  # Async write to slower backends


class CacheManager:
    """
    Intelligent cache manager with multi-tier caching.

    Provides automatic cache backend selection, cache warming,
    and intelligent invalidation strategies.
    """

    def __init__(self, strategy: CacheStrategy = CacheStrategy.TIERED):
        """
        Initialize cache manager.

        Args:
            strategy: Caching strategy to use
        """
        self.strategy = strategy
        self.config = get_scaling_config()
        self.cache_config = self.config.get_cache_config()

        # Initialize backends
        self.memory_cache = MemoryCache(
            max_size=min(50000, self.cache_config["max_memory_mb"] * 10),  # ~10 items per MB
            default_ttl=self.cache_config["default_ttl"]
        )

        self.redis_cache = None
        if self.config._system_resources and self.config._system_resources.total_memory_gb > 4:
            # Only use Redis if we have sufficient memory
            redis_url = getattr(self.config, 'redis_url', None)
            if redis_url:
                self.redis_cache = RedisCache(
                    redis_url=redis_url,
                    default_ttl=self.cache_config["default_ttl"]
                )

        self.disk_cache = DiskCache(
            max_size_mb=self.cache_config["max_memory_mb"] * 2,  # 2x memory for disk
            default_ttl=self.cache_config["default_ttl"] * 24  # Longer TTL for disk
        )

        # Cache warming and invalidation
        self._warm_cache_keys: Set[str] = set()
        self._invalidation_patterns: Dict[str, Set[str]] = {}
        self._stats = {
            "requests": 0,
            "hits": 0,
            "misses": 0,
            "write_throughs": 0,
            "invalidations": 0
        }

        # Background tasks
        self._warming_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Start cache manager background tasks."""
        if self._running:
            return

        self._running = True

        # Start background tasks
        self._warming_task = asyncio.create_task(self._cache_warming_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info(f"Cache manager started with strategy: {self.strategy.value}")

    async def stop(self):
        """Stop cache manager background tasks."""
        self._running = False

        if self._warming_task:
            self._warming_task.cancel()
            try:
                await self._warming_task
            except asyncio.CancelledError:
                pass

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        logger.info("Cache manager stopped")

    async def get(self, key: str) -> Optional[Any]:
        """
        Get a value from cache using the configured strategy.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        self._stats["requests"] += 1

        if self.strategy == CacheStrategy.MEMORY_ONLY:
            result = await self.memory_cache.get(key)
        elif self.strategy == CacheStrategy.REDIS_ONLY:
            result = await self.redis_cache.get(key) if self.redis_cache else None
        elif self.strategy == CacheStrategy.DISK_ONLY:
            result = await self.disk_cache.get(key)
        else:  # TIERED, WRITE_THROUGH, WRITE_BEHIND
            result = await self._get_tiered(key)

        if result is not None:
            self._stats["hits"] += 1
        else:
            self._stats["misses"] += 1

        return result

    async def set(self, key: str, value: Any, ttl: Optional[int] = None,
                  warm: bool = False, invalidate_patterns: Optional[List[str]] = None) -> bool:
        """
        Set a value in cache using the configured strategy.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            warm: Whether to add key to warming set
            invalidate_patterns: Patterns to invalidate when this key changes

        Returns:
            True if successful
        """
        success = False

        if self.strategy == CacheStrategy.MEMORY_ONLY:
            success = await self.memory_cache.set(key, value, ttl)
        elif self.strategy == CacheStrategy.REDIS_ONLY:
            success = await self.redis_cache.set(key, value, ttl) if self.redis_cache else False
        elif self.strategy == CacheStrategy.DISK_ONLY:
            success = await self.disk_cache.set(key, value, ttl)
        else:
            success = await self._set_tiered(key, value, ttl)

        # Add to warm cache if requested
        if warm and success:
            self._warm_cache_keys.add(key)

        # Set up invalidation patterns
        if invalidate_patterns and success:
            for pattern in invalidate_patterns:
                if pattern not in self._invalidation_patterns:
                    self._invalidation_patterns[pattern] = set()
                self._invalidation_patterns[pattern].add(key)

        return success

    async def delete(self, key: str) -> bool:
        """
        Delete a value from all cache backends.

        Args:
            key: Cache key to delete

        Returns:
            True if at least one backend deleted the key
        """
        results = []

        # Delete from all backends
        results.append(await self.memory_cache.delete(key))

        if self.redis_cache:
            results.append(await self.redis_cache.delete(key))

        results.append(await self.disk_cache.delete(key))

        # Remove from warm cache
        self._warm_cache_keys.discard(key)

        # Clean up invalidation patterns
        for pattern_keys in self._invalidation_patterns.values():
            pattern_keys.discard(key)

        return any(results)

    async def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching a pattern.

        Args:
            pattern: Pattern to match keys against
        """
        if pattern in self._invalidation_patterns:
            keys_to_invalidate = self._invalidation_patterns[pattern].copy()
            for key in keys_to_invalidate:
                await self.delete(key)

            del self._invalidation_patterns[pattern]
            self._stats["invalidations"] += len(keys_to_invalidate)

    async def warm_cache(self, keys: List[str], data_loader: Callable[[str], Any]):
        """
        Warm cache with specified keys using a data loader function.

        Args:
            keys: List of keys to warm
            data_loader: Function to load data for a key
        """
        for key in keys:
            try:
                if not await self.exists(key):
                    value = await data_loader(key) if asyncio.iscoroutinefunction(data_loader) else data_loader(key)
                    if value is not None:
                        await self.set(key, value, warm=True)
            except Exception as e:
                logger.warning(f"Failed to warm cache for key {key}: {e}")

    async def exists(self, key: str) -> bool:
        """Check if key exists in any cache backend."""
        if await self.memory_cache.exists(key):
            return True

        if self.redis_cache and await self.redis_cache.exists(key):
            return True

        return await self.disk_cache.exists(key)

    async def clear_all(self) -> bool:
        """Clear all cache backends."""
        results = []

        results.append(await self.memory_cache.clear())

        if self.redis_cache:
            results.append(await self.redis_cache.clear())

        results.append(await self.disk_cache.clear())

        # Clear internal state
        self._warm_cache_keys.clear()
        self._invalidation_patterns.clear()

        return all(results)

    async def _get_tiered(self, key: str) -> Optional[Any]:
        """Get value using tiered cache strategy."""
        # Try memory cache first (fastest)
        value = await self.memory_cache.get(key)
        if value is not None:
            return value

        # Try Redis cache (medium speed)
        if self.redis_cache:
            value = await self.redis_cache.get(key)
            if value is not None:
                # Promote to memory cache
                await self.memory_cache.set(key, value)
                return value

        # Try disk cache (slowest)
        value = await self.disk_cache.get(key)
        if value is not None:
            # Promote to memory and Redis caches
            await self.memory_cache.set(key, value)
            if self.redis_cache:
                await self.redis_cache.set(key, value)
            return value

        return None

    async def _set_tiered(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value using tiered cache strategy."""
        results = []

        if self.strategy == CacheStrategy.WRITE_THROUGH:
            # Write to all backends synchronously
            results.append(await self.memory_cache.set(key, value, ttl))

            if self.redis_cache:
                results.append(await self.redis_cache.set(key, value, ttl))

            results.append(await self.disk_cache.set(key, value, ttl))

            if any(results):
                self._stats["write_throughs"] += 1

            return any(results)

        elif self.strategy == CacheStrategy.WRITE_BEHIND:
            # Write to memory immediately, others asynchronously
            memory_result = await self.memory_cache.set(key, value, ttl)

            # Schedule async writes
            if self.redis_cache:
                asyncio.create_task(self.redis_cache.set(key, value, ttl))

            asyncio.create_task(self.disk_cache.set(key, value, ttl))

            return memory_result

        else:  # TIERED
            # Write to memory cache only initially
            return await self.memory_cache.set(key, value, ttl)

    async def _cache_warming_loop(self):
        """Background task for cache warming."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                if self._warm_cache_keys:
                    logger.debug(f"Warming {len(self._warm_cache_keys)} cache keys")

                    # Implement cache warming logic here
                    # This would typically reload data for keys that are likely to be accessed

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache warming loop: {e}")

    async def _cleanup_loop(self):
        """Background task for cache cleanup and optimization."""
        while self._running:
            try:
                await asyncio.sleep(1800)  # Run every 30 minutes

                # Clean up empty invalidation patterns
                empty_patterns = [
                    pattern for pattern, keys in self._invalidation_patterns.items()
                    if not keys
                ]
                for pattern in empty_patterns:
                    del self._invalidation_patterns[pattern]

                logger.debug("Cache cleanup completed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup loop: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        total_requests = self._stats["requests"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        stats = {
            "strategy": self.strategy.value,
            "total_requests": total_requests,
            "hit_rate": round(hit_rate, 2),
            "warm_keys_count": len(self._warm_cache_keys),
            "invalidation_patterns": len(self._invalidation_patterns),
            "backends": {
                "memory": self.memory_cache.get_stats(),
                "disk": self.disk_cache.get_stats()
            },
            **self._stats
        }

        if self.redis_cache:
            stats["backends"]["redis"] = self.redis_cache.get_stats()

        return stats

    def get_cache_key(self, prefix: str, **kwargs) -> str:
        """
        Generate a cache key from prefix and parameters.

        Args:
            prefix: Cache key prefix
            **kwargs: Parameters to include in key

        Returns:
            Generated cache key
        """
        # Sort kwargs for consistent key generation
        sorted_params = sorted(kwargs.items())
        params_str = json.dumps(sorted_params, sort_keys=True)
        params_hash = hashlib.md5(params_str.encode()).hexdigest()[:8]

        return f"{prefix}:{params_hash}"


# Global cache manager instance
_cache_manager: Optional[CacheManager] = None


async def start_cache_manager(strategy: CacheStrategy = CacheStrategy.TIERED):
    """Start the global cache manager."""
    global _cache_manager

    if _cache_manager is not None and _cache_manager._running:
        logger.warning("Cache manager is already running")
        return

    _cache_manager = CacheManager(strategy)
    await _cache_manager.start()


async def stop_cache_manager():
    """Stop the global cache manager."""
    global _cache_manager

    if _cache_manager is not None:
        await _cache_manager.stop()
        _cache_manager = None


def get_cache_manager() -> Optional[CacheManager]:
    """Get the global cache manager instance."""
    return _cache_manager