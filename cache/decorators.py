"""
Cache decorators for easy integration with the authentication system.

This module provides decorators for automatic caching of function results,
with intelligent cache key generation and invalidation.
"""

import asyncio
import functools
import inspect
import logging
from typing import Any, Callable, Optional, List, Union
import hashlib
import json

from .manager import get_cache_manager

logger = logging.getLogger(__name__)


def cached(
    ttl: Optional[int] = None,
    key_prefix: Optional[str] = None,
    warm: bool = False,
    invalidate_patterns: Optional[List[str]] = None,
    skip_cache_if: Optional[Callable] = None
):
    """
    Decorator to cache function results.

    Args:
        ttl: Time to live in seconds
        key_prefix: Custom prefix for cache keys
        warm: Whether to add to warm cache
        invalidate_patterns: Patterns to invalidate when function result changes
        skip_cache_if: Function to determine if caching should be skipped

    Example:
        @cached(ttl=3600, key_prefix="user_profile")
        async def get_user_profile(user_id: str):
            return await db.get_user(user_id)
    """
    def decorator(func: Callable) -> Callable:
        # Generate key prefix if not provided
        prefix = key_prefix or f"{func.__module__}.{func.__name__}"

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()
            if not cache_manager:
                # No cache available, call function directly
                return await func(*args, **kwargs)

            # Check if caching should be skipped
            if skip_cache_if and skip_cache_if(*args, **kwargs):
                return await func(*args, **kwargs)

            # Generate cache key
            cache_key = _generate_cache_key(prefix, args, kwargs)

            # Try to get from cache
            cached_result = await cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Call function and cache result
            result = await func(*args, **kwargs)
            if result is not None:
                await cache_manager.set(
                    cache_key,
                    result,
                    ttl=ttl,
                    warm=warm,
                    invalidate_patterns=invalidate_patterns
                )

            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()
            if not cache_manager:
                # No cache available, call function directly
                return func(*args, **kwargs)

            # Check if caching should be skipped
            if skip_cache_if and skip_cache_if(*args, **kwargs):
                return func(*args, **kwargs)

            # Generate cache key
            cache_key = _generate_cache_key(prefix, args, kwargs)

            # For sync functions, we need to handle async cache operations
            async def _handle_sync_cache():
                # Try to get from cache
                cached_result = await cache_manager.get(cache_key)
                if cached_result is not None:
                    return cached_result

                # Call function and cache result
                result = func(*args, **kwargs)
                if result is not None:
                    await cache_manager.set(
                        cache_key,
                        result,
                        ttl=ttl,
                        warm=warm,
                        invalidate_patterns=invalidate_patterns
                    )

                return result

            # Run in event loop if available, otherwise use asyncio.run
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Create task for later execution
                    task = asyncio.create_task(_handle_sync_cache())
                    return task
                else:
                    return loop.run_until_complete(_handle_sync_cache())
            except RuntimeError:
                return asyncio.run(_handle_sync_cache())

        # Return appropriate wrapper based on function type
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def cache_result(
    key: Union[str, Callable],
    ttl: Optional[int] = None,
    warm: bool = False
):
    """
    Decorator to cache function results with a custom key generator.

    Args:
        key: Cache key or function to generate cache key
        ttl: Time to live in seconds
        warm: Whether to add to warm cache

    Example:
        @cache_result(
            key=lambda user_id: f"user_credentials:{user_id}",
            ttl=1800
        )
        async def get_user_credentials(user_id: str):
            return await db.get_credentials(user_id)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()
            if not cache_manager:
                return await func(*args, **kwargs)

            # Generate cache key
            if callable(key):
                cache_key = key(*args, **kwargs)
            else:
                cache_key = str(key)

            # Try to get from cache
            cached_result = await cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Call function and cache result
            result = await func(*args, **kwargs)
            if result is not None:
                await cache_manager.set(cache_key, result, ttl=ttl, warm=warm)

            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()
            if not cache_manager:
                return func(*args, **kwargs)

            # Generate cache key
            if callable(key):
                cache_key = key(*args, **kwargs)
            else:
                cache_key = str(key)

            async def _handle_cache():
                # Try to get from cache
                cached_result = await cache_manager.get(cache_key)
                if cached_result is not None:
                    return cached_result

                # Call function and cache result
                result = func(*args, **kwargs)
                if result is not None:
                    await cache_manager.set(cache_key, result, ttl=ttl, warm=warm)

                return result

            try:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(_handle_cache())
            except RuntimeError:
                return asyncio.run(_handle_cache())

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def invalidate_cache(*patterns: str):
    """
    Decorator to invalidate cache patterns after function execution.

    Args:
        *patterns: Cache patterns to invalidate

    Example:
        @invalidate_cache("user_profile:*", "user_permissions:*")
        async def update_user(user_id: str, data: dict):
            return await db.update_user(user_id, data)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)

            # Invalidate cache patterns after successful execution
            cache_manager = get_cache_manager()
            if cache_manager:
                for pattern in patterns:
                    # Replace placeholders with actual values
                    formatted_pattern = _format_pattern(pattern, args, kwargs)
                    await cache_manager.invalidate_pattern(formatted_pattern)

            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            # Invalidate cache patterns after successful execution
            cache_manager = get_cache_manager()
            if cache_manager:
                async def _invalidate():
                    for pattern in patterns:
                        formatted_pattern = _format_pattern(pattern, args, kwargs)
                        await cache_manager.invalidate_pattern(formatted_pattern)

                try:
                    loop = asyncio.get_event_loop()
                    asyncio.create_task(_invalidate())
                except RuntimeError:
                    asyncio.run(_invalidate())

            return result

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


class CacheService:
    """Service class for manual cache operations."""

    def __init__(self):
        """Initialize cache service."""
        self.cache_manager = get_cache_manager()

    async def get_or_set(
        self,
        key: str,
        data_loader: Callable,
        ttl: Optional[int] = None,
        **loader_kwargs
    ) -> Any:
        """
        Get value from cache or set it using data loader.

        Args:
            key: Cache key
            data_loader: Function to load data if not in cache
            ttl: Time to live in seconds
            **loader_kwargs: Arguments for data loader

        Returns:
            Cached or loaded value
        """
        if not self.cache_manager:
            return await data_loader(**loader_kwargs) if inspect.iscoroutinefunction(data_loader) else data_loader(**loader_kwargs)

        # Try to get from cache
        cached_value = await self.cache_manager.get(key)
        if cached_value is not None:
            return cached_value

        # Load data and cache it
        if inspect.iscoroutinefunction(data_loader):
            value = await data_loader(**loader_kwargs)
        else:
            value = data_loader(**loader_kwargs)

        if value is not None:
            await self.cache_manager.set(key, value, ttl=ttl)

        return value

    async def invalidate_user_cache(self, user_id: str):
        """Invalidate all cache entries for a specific user."""
        if self.cache_manager:
            patterns = [
                f"user_profile:{user_id}",
                f"user_credentials:{user_id}",
                f"user_sessions:{user_id}",
                f"user_permissions:{user_id}",
                f"user_risk_score:{user_id}"
            ]
            for pattern in patterns:
                await self.cache_manager.invalidate_pattern(pattern)

    async def warm_user_cache(self, user_id: str):
        """Warm cache for a specific user."""
        if not self.cache_manager:
            return

        # Define cache warming functions
        async def load_user_profile(uid):
            # This would load user profile from database
            # Implementation depends on your data layer
            pass

        async def load_user_credentials(uid):
            # This would load user credentials from database
            pass

        # Warm cache keys
        warm_tasks = [
            self.cache_manager.warm_cache([f"user_profile:{user_id}"], load_user_profile),
            self.cache_manager.warm_cache([f"user_credentials:{user_id}"], load_user_credentials),
        ]

        await asyncio.gather(*warm_tasks, return_exceptions=True)

    async def get_cache_stats(self) -> dict:
        """Get cache statistics."""
        if self.cache_manager:
            return self.cache_manager.get_stats()
        return {"error": "Cache manager not available"}


def _generate_cache_key(prefix: str, args: tuple, kwargs: dict) -> str:
    """Generate a cache key from function arguments."""
    # Convert args and kwargs to a consistent string representation
    key_data = {
        "args": [_serialize_arg(arg) for arg in args],
        "kwargs": {k: _serialize_arg(v) for k, v in sorted(kwargs.items())}
    }

    # Create hash of the serialized data
    key_str = json.dumps(key_data, sort_keys=True)
    key_hash = hashlib.md5(key_str.encode()).hexdigest()[:8]

    return f"{prefix}:{key_hash}"


def _serialize_arg(arg: Any) -> str:
    """Serialize an argument for cache key generation."""
    if isinstance(arg, (str, int, float, bool)):
        return str(arg)
    elif isinstance(arg, dict):
        return json.dumps(arg, sort_keys=True)
    elif isinstance(arg, (list, tuple)):
        return json.dumps(list(arg))
    else:
        # For other types, use string representation
        return str(arg)


def _format_pattern(pattern: str, args: tuple, kwargs: dict) -> str:
    """Format a cache pattern with function arguments."""
    # Simple pattern formatting - can be enhanced as needed
    try:
        # Try to format with kwargs first
        if kwargs:
            return pattern.format(**kwargs)
        # Fall back to positional formatting
        elif args:
            return pattern.format(*args)
        else:
            return pattern
    except (KeyError, IndexError):
        # If formatting fails, return pattern as-is
        return pattern


# Global cache service instance
_cache_service: Optional[CacheService] = None


def get_cache_service() -> CacheService:
    """Get or create global cache service instance."""
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service