"""
Cache backend implementations for the intelligent caching system.

This module provides various cache backends including memory, Redis-compatible,
and disk-based caching with automatic failover and performance optimization.
"""

import asyncio
import json
import logging
import pickle
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from functools import lru_cache
import hashlib
import tempfile

from app.config.scaling import get_scaling_config

logger = logging.getLogger(__name__)


class CacheBackend(ABC):
    """Abstract base class for cache backends."""

    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in the cache with optional TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a value from the cache."""
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        pass

    @abstractmethod
    async def clear(self) -> bool:
        """Clear all values from the cache."""
        pass

    @abstractmethod
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a pattern."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        pass


class MemoryCache(CacheBackend):
    """High-performance in-memory cache with LRU eviction."""

    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        """
        Initialize memory cache.

        Args:
            max_size: Maximum number of items to store
            default_ttl: Default TTL in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, float] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0
        }

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from memory cache."""
        if key not in self._cache:
            self._stats["misses"] += 1
            return None

        item = self._cache[key]

        # Check if expired
        if item["expires_at"] and time.time() > item["expires_at"]:
            await self.delete(key)
            self._stats["misses"] += 1
            return None

        # Update access time for LRU
        self._access_times[key] = time.time()
        self._stats["hits"] += 1
        return item["value"]

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in memory cache."""
        if ttl is None:
            ttl = self.default_ttl

        expires_at = time.time() + ttl if ttl > 0 else None

        # Evict if at capacity
        if len(self._cache) >= self.max_size and key not in self._cache:
            await self._evict_lru()

        self._cache[key] = {
            "value": value,
            "expires_at": expires_at,
            "created_at": time.time()
        }
        self._access_times[key] = time.time()
        self._stats["sets"] += 1
        return True

    async def delete(self, key: str) -> bool:
        """Delete a value from memory cache."""
        if key in self._cache:
            del self._cache[key]
            del self._access_times[key]
            self._stats["deletes"] += 1
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        if key not in self._cache:
            return False

        item = self._cache[key]
        if item["expires_at"] and time.time() > item["expires_at"]:
            await self.delete(key)
            return False

        return True

    async def clear(self) -> bool:
        """Clear all values from memory cache."""
        self._cache.clear()
        self._access_times.clear()
        return True

    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a pattern."""
        if pattern == "*":
            return list(self._cache.keys())

        # Simple pattern matching (can be enhanced)
        import fnmatch
        return [key for key in self._cache.keys() if fnmatch.fnmatch(key, pattern)]

    async def _evict_lru(self):
        """Evict least recently used item."""
        if not self._access_times:
            return

        lru_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
        await self.delete(lru_key)
        self._stats["evictions"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get memory cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "backend": "memory",
            "size": len(self._cache),
            "max_size": self.max_size,
            "hit_rate": round(hit_rate, 2),
            **self._stats
        }


class DiskCache(CacheBackend):
    """Disk-based cache for persistent storage with compression."""

    def __init__(self, cache_dir: Optional[str] = None, max_size_mb: int = 1000, default_ttl: int = 3600):
        """
        Initialize disk cache.

        Args:
            cache_dir: Directory for cache files
            max_size_mb: Maximum cache size in MB
            default_ttl: Default TTL in seconds
        """
        self.cache_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / "biometric_auth_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self._index_file = self.cache_dir / "index.json"
        self._index: Dict[str, Dict[str, Any]] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "evictions": 0
        }
        asyncio.create_task(self._load_index())

    async def _load_index(self):
        """Load cache index from disk."""
        try:
            if self._index_file.exists():
                with open(self._index_file, 'r') as f:
                    self._index = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load cache index: {e}")
            self._index = {}

    async def _save_index(self):
        """Save cache index to disk."""
        try:
            with open(self._index_file, 'w') as f:
                json.dump(self._index, f)
        except Exception as e:
            logger.error(f"Failed to save cache index: {e}")

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key."""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from disk cache."""
        if key not in self._index:
            self._stats["misses"] += 1
            return None

        item = self._index[key]

        # Check if expired
        if item["expires_at"] and time.time() > item["expires_at"]:
            await self.delete(key)
            self._stats["misses"] += 1
            return None

        # Load from disk
        cache_path = self._get_cache_path(key)
        try:
            with open(cache_path, 'rb') as f:
                value = pickle.load(f)

            # Update access time
            self._index[key]["accessed_at"] = time.time()
            self._stats["hits"] += 1
            return value
        except Exception as e:
            logger.warning(f"Failed to load cache file {cache_path}: {e}")
            await self.delete(key)
            self._stats["misses"] += 1
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in disk cache."""
        if ttl is None:
            ttl = self.default_ttl

        expires_at = time.time() + ttl if ttl > 0 else None
        cache_path = self._get_cache_path(key)

        try:
            # Check disk space and evict if necessary
            await self._ensure_disk_space()

            # Save to disk
            with open(cache_path, 'wb') as f:
                pickle.dump(value, f)

            # Update index
            file_size = cache_path.stat().st_size
            self._index[key] = {
                "expires_at": expires_at,
                "created_at": time.time(),
                "accessed_at": time.time(),
                "size": file_size
            }

            await self._save_index()
            self._stats["sets"] += 1
            return True

        except Exception as e:
            logger.error(f"Failed to save cache file {cache_path}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete a value from disk cache."""
        if key not in self._index:
            return False

        cache_path = self._get_cache_path(key)
        try:
            if cache_path.exists():
                cache_path.unlink()
            del self._index[key]
            await self._save_index()
            self._stats["deletes"] += 1
            return True
        except Exception as e:
            logger.error(f"Failed to delete cache file {cache_path}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        if key not in self._index:
            return False

        item = self._index[key]
        if item["expires_at"] and time.time() > item["expires_at"]:
            await self.delete(key)
            return False

        return True

    async def clear(self) -> bool:
        """Clear all values from disk cache."""
        try:
            for cache_file in self.cache_dir.glob("*.cache"):
                cache_file.unlink()
            self._index.clear()
            await self._save_index()
            return True
        except Exception as e:
            logger.error(f"Failed to clear disk cache: {e}")
            return False

    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a pattern."""
        if pattern == "*":
            return list(self._index.keys())

        import fnmatch
        return [key for key in self._index.keys() if fnmatch.fnmatch(key, pattern)]

    async def _ensure_disk_space(self):
        """Ensure disk cache doesn't exceed size limit."""
        total_size = sum(item["size"] for item in self._index.values())

        if total_size > self.max_size_bytes:
            # Evict oldest accessed files
            sorted_keys = sorted(
                self._index.keys(),
                key=lambda k: self._index[k]["accessed_at"]
            )

            for key in sorted_keys:
                if total_size <= self.max_size_bytes * 0.8:  # Target 80% of max
                    break

                total_size -= self._index[key]["size"]
                await self.delete(key)
                self._stats["evictions"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get disk cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        total_size = sum(item["size"] for item in self._index.values())

        return {
            "backend": "disk",
            "size": len(self._index),
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "max_size_mb": round(self.max_size_bytes / (1024 * 1024), 2),
            "hit_rate": round(hit_rate, 2),
            **self._stats
        }


class RedisCache(CacheBackend):
    """Redis-compatible cache backend with fallback to memory cache."""

    def __init__(self, redis_url: Optional[str] = None, default_ttl: int = 3600):
        """
        Initialize Redis cache.

        Args:
            redis_url: Redis connection URL
            default_ttl: Default TTL in seconds
        """
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self.redis_client = None
        self.fallback_cache = MemoryCache(max_size=5000, default_ttl=default_ttl)
        self._use_fallback = False
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "redis_errors": 0
        }
        asyncio.create_task(self._initialize_redis())

    async def _initialize_redis(self):
        """Initialize Redis connection."""
        if not self.redis_url:
            self._use_fallback = True
            logger.info("Redis URL not provided, using memory cache fallback")
            return

        try:
            import aioredis
            self.redis_client = aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis cache initialized successfully")
        except ImportError:
            logger.warning("aioredis not installed, using memory cache fallback")
            self._use_fallback = True
        except Exception as e:
            logger.warning(f"Failed to connect to Redis, using fallback: {e}")
            self._use_fallback = True

    async def _execute_redis_command(self, func, *args, **kwargs):
        """Execute Redis command with fallback handling."""
        if self._use_fallback or not self.redis_client:
            return None

        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Redis command failed, using fallback: {e}")
            self._stats["redis_errors"] += 1
            self._use_fallback = True
            return None

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from Redis or fallback cache."""
        if self._use_fallback:
            return await self.fallback_cache.get(key)

        result = await self._execute_redis_command(self.redis_client.get, key)
        if result is not None:
            try:
                value = pickle.loads(result)
                self._stats["hits"] += 1
                return value
            except Exception as e:
                logger.warning(f"Failed to deserialize cached value: {e}")

        self._stats["misses"] += 1
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in Redis or fallback cache."""
        if self._use_fallback:
            return await self.fallback_cache.set(key, value, ttl)

        if ttl is None:
            ttl = self.default_ttl

        try:
            serialized_value = pickle.dumps(value)
            result = await self._execute_redis_command(
                self.redis_client.setex, key, ttl, serialized_value
            )
            if result:
                self._stats["sets"] += 1
                return True
        except Exception as e:
            logger.warning(f"Failed to serialize value for caching: {e}")

        return False

    async def delete(self, key: str) -> bool:
        """Delete a value from Redis or fallback cache."""
        if self._use_fallback:
            return await self.fallback_cache.delete(key)

        result = await self._execute_redis_command(self.redis_client.delete, key)
        if result:
            self._stats["deletes"] += 1
            return True
        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis or fallback cache."""
        if self._use_fallback:
            return await self.fallback_cache.exists(key)

        result = await self._execute_redis_command(self.redis_client.exists, key)
        return bool(result)

    async def clear(self) -> bool:
        """Clear all values from Redis or fallback cache."""
        if self._use_fallback:
            return await self.fallback_cache.clear()

        result = await self._execute_redis_command(self.redis_client.flushdb)
        return result is not None

    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a pattern."""
        if self._use_fallback:
            return await self.fallback_cache.keys(pattern)

        result = await self._execute_redis_command(self.redis_client.keys, pattern)
        if result:
            return [key.decode() if isinstance(key, bytes) else key for key in result]
        return []

    def get_stats(self) -> Dict[str, Any]:
        """Get Redis cache statistics."""
        if self._use_fallback:
            stats = self.fallback_cache.get_stats()
            stats["backend"] = "redis_fallback"
            stats["redis_errors"] = self._stats["redis_errors"]
            return stats

        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "backend": "redis",
            "hit_rate": round(hit_rate, 2),
            "using_fallback": self._use_fallback,
            **self._stats
        }