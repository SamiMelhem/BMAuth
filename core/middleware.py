"""
BMAuth middleware for FastAPI integration.

This module provides middleware for automatic request processing,
rate limiting, and security headers.
"""

from typing import Callable, Dict, Any
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time
import logging

from .config import BMAuthConfig
from ..security.rate_limiting import RateLimiter

logger = logging.getLogger(__name__)


class BMAuthMiddleware(BaseHTTPMiddleware):
    """
    BMAuth middleware for FastAPI applications.

    This middleware handles:
    - Security headers
    - Rate limiting
    - Request logging
    - Performance monitoring
    """

    def __init__(self, config: BMAuthConfig):
        """
        Initialize BMAuth middleware.

        Args:
            config: BMAuth configuration
        """
        self.config = config
        self.rate_limiter = RateLimiter() if config.enable_rate_limiting else None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process incoming requests.

        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler

        Returns:
            FastAPI response object
        """
        start_time = time.time()

        # Add security headers
        response = await self._process_request(request, call_next)

        # Add performance headers
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)

        # Add security headers
        self._add_security_headers(response)

        return response

    async def _process_request(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request with rate limiting and logging.

        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler

        Returns:
            FastAPI response object
        """
        # Rate limiting for authentication endpoints
        if self.rate_limiter and self._is_auth_endpoint(request):
            client_ip = self._get_client_ip(request)

            if not await self.rate_limiter.is_allowed(
                key=f"auth:{client_ip}",
                limit=self.config.rate_limit_requests,
                window=self.config.rate_limit_window
            ):
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded. Please try again later."
                )

        # Log request if debug enabled
        if self.config.debug:
            logger.debug(f"Processing request: {request.method} {request.url}")

        # Process request
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logger.error(f"Request processing failed: {e}")
            raise

    def _is_auth_endpoint(self, request: Request) -> bool:
        """
        Check if the request is for an authentication endpoint.

        Args:
            request: FastAPI request object

        Returns:
            True if auth endpoint, False otherwise
        """
        auth_paths = [
            "/auth/login",
            "/auth/register",
            "/auth/webauthn",
            "/bmauth/auth"
        ]

        return any(request.url.path.startswith(path) for path in auth_paths)

    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address from request.

        Args:
            request: FastAPI request object

        Returns:
            Client IP address
        """
        # Check for forwarded IP headers
        forwarded_ip = request.headers.get("X-Forwarded-For")
        if forwarded_ip:
            # Take the first IP in case of multiple proxies
            return forwarded_ip.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"

    def _add_security_headers(self, response: Response) -> None:
        """
        Add security headers to the response.

        Args:
            response: FastAPI response object
        """
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-BMAuth-Version": "1.0.0"
        }

        for header, value in security_headers.items():
            response.headers[header] = value

        # Add HSTS header for HTTPS
        if self.config.rp_origins and any("https://" in origin for origin in self.config.rp_origins):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    def get_kwargs(self) -> Dict[str, Any]:
        """
        Get middleware initialization kwargs.

        Returns:
            Dictionary of kwargs for middleware initialization
        """
        return {
            "config": self.config
        }