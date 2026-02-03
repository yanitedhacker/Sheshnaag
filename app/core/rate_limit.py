"""
Rate Limiting middleware for API protection.

Author: Security Enhancement

Implements a simple in-memory rate limiter using sliding window algorithm.
For production with multiple instances, consider using Redis-based rate limiting.
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import Request, HTTPException, status

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    In-memory rate limiter using sliding window algorithm.

    For distributed deployments, replace with Redis-based implementation.
    """

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_limit: int = 10
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_minute: Maximum requests per minute per IP
            requests_per_hour: Maximum requests per hour per IP
            burst_limit: Maximum burst requests in 1 second
        """
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_limit = burst_limit

        # Storage: IP -> list of request timestamps
        self.requests: Dict[str, List[datetime]] = defaultdict(list)
        self._lock = asyncio.Lock()

        # Cleanup interval
        self._last_cleanup = datetime.now(timezone.utc)
        self._cleanup_interval = timedelta(minutes=5)

    async def check(self, request: Request) -> None:
        """
        Check if request should be allowed.

        Args:
            request: FastAPI request object

        Raises:
            HTTPException: If rate limit exceeded
        """
        client_ip = self._get_client_ip(request)
        now = datetime.now(timezone.utc)

        async with self._lock:
            # Periodic cleanup
            if now - self._last_cleanup > self._cleanup_interval:
                await self._cleanup_old_requests()
                self._last_cleanup = now

            # Get request history for this IP
            request_times = self.requests[client_ip]

            # Clean old requests for this IP
            one_hour_ago = now - timedelta(hours=1)
            self.requests[client_ip] = [t for t in request_times if t > one_hour_ago]
            request_times = self.requests[client_ip]

            # Check burst limit (last 1 second)
            one_second_ago = now - timedelta(seconds=1)
            recent_burst = sum(1 for t in request_times if t > one_second_ago)
            if recent_burst >= self.burst_limit:
                logger.warning(f"Burst limit exceeded for IP: {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please slow down.",
                    headers={"Retry-After": "1"}
                )

            # Check per-minute limit
            one_minute_ago = now - timedelta(minutes=1)
            recent_minute = sum(1 for t in request_times if t > one_minute_ago)
            if recent_minute >= self.requests_per_minute:
                logger.warning(f"Per-minute rate limit exceeded for IP: {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Try again in a minute.",
                    headers={"Retry-After": "60"}
                )

            # Check per-hour limit
            if len(request_times) >= self.requests_per_hour:
                logger.warning(f"Per-hour rate limit exceeded for IP: {client_ip}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Hourly rate limit exceeded. Try again later.",
                    headers={"Retry-After": "3600"}
                )

            # Record this request
            self.requests[client_ip].append(now)

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP from request, considering proxies.

        Args:
            request: FastAPI request object

        Returns:
            Client IP address
        """
        # Check for forwarded headers (when behind proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (original client)
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Direct connection
        if request.client:
            return request.client.host

        return "unknown"

    async def _cleanup_old_requests(self) -> None:
        """Remove old request records to prevent memory growth."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        empty_ips = []

        for ip, times in self.requests.items():
            self.requests[ip] = [t for t in times if t > cutoff]
            if not self.requests[ip]:
                empty_ips.append(ip)

        # Remove empty entries
        for ip in empty_ips:
            del self.requests[ip]

        if empty_ips:
            logger.debug(f"Cleaned up rate limit records for {len(empty_ips)} IPs")

    def get_remaining(self, request: Request) -> Dict[str, int]:
        """
        Get remaining request allowance for a client.

        Args:
            request: FastAPI request object

        Returns:
            Dict with remaining requests per window
        """
        client_ip = self._get_client_ip(request)
        now = datetime.now(timezone.utc)
        request_times = self.requests.get(client_ip, [])

        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        minute_count = sum(1 for t in request_times if t > one_minute_ago)
        hour_count = sum(1 for t in request_times if t > one_hour_ago)

        return {
            "remaining_per_minute": max(0, self.requests_per_minute - minute_count),
            "remaining_per_hour": max(0, self.requests_per_hour - hour_count),
            "limit_per_minute": self.requests_per_minute,
            "limit_per_hour": self.requests_per_hour
        }


# Default rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=100,
    requests_per_hour=2000,
    burst_limit=20
)


# Whitelist for IPs that bypass rate limiting (e.g., monitoring)
RATE_LIMIT_WHITELIST = {
    "127.0.0.1",
    "::1",
}


async def check_rate_limit(request: Request) -> None:
    """
    Rate limit check dependency.

    Can be used as a dependency in routes or as middleware.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Skip rate limiting for whitelisted IPs
    if client_ip in RATE_LIMIT_WHITELIST:
        return

    # Skip rate limiting for health checks
    if request.url.path in {"/health", "/", "/metrics"}:
        return

    await rate_limiter.check(request)
