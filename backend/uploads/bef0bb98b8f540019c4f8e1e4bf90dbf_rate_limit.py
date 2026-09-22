import hashlib
import hmac
import logging
import os
import secrets
import time
from collections import defaultdict
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory sliding-window rate limiter with IP blocking and progressive delays."""

    def __init__(
        self,
        app,
        default_limit: int = 60,
        default_window: int = 60,
        auth_limit: int = 10,
        auth_window: int = 60,
        login_limit: int = 5,
        login_window: int = 60,
        otp_limit: int = 8,
        otp_window: int = 60,
        download_limit: int = 20,
        download_window: int = 60,
        block_threshold: int = 50,
        block_duration: int = 900,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.default_window = default_window
        self.auth_limit = auth_limit
        self.auth_window = auth_window
        self.login_limit = login_limit
        self.login_window = login_window
        self.otp_limit = otp_limit
        self.otp_window = otp_window
        self.download_limit = download_limit
        self.download_window = download_window
        self.block_threshold = block_threshold
        self.block_duration = block_duration

        self._requests: dict[str, list[float]] = defaultdict(list)
        self._blocked: dict[str, float] = {}
        self._progressive_delay: dict[str, int] = {}
        self._last_cleanup = time.time()
        self._suspicious_patterns: dict[str, list[float]] = defaultdict(list)

    def _cleanup_old_entries(self) -> None:
        now = time.time()
        if now - self._last_cleanup < 120:
            return
        self._last_cleanup = now
        max_window = max(self.default_window, self.block_duration)
        cutoff = now - max_window
        expired_keys = [
            k for k, v in self._requests.items() if not v or v[-1] < cutoff
        ]
        for k in expired_keys:
            del self._requests[k]
        expired_blocks = [k for k, v in self._blocked.items() if now > v]
        for k in expired_blocks:
            del self._blocked[k]
        expired_suspicious = [k for k, v in self._suspicious_patterns.items() if not v or v[-1] < cutoff]
        for k in expired_suspicious:
            del self._suspicious_patterns[k]

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "unknown"

    def _classify_endpoint(self, path: str, method: str) -> tuple[int, int]:
        if path.startswith("/api/v1/auth/login") and method == "POST":
            return self.login_limit, self.login_window
        if path.startswith("/api/v1/auth/verify-otp") and method == "POST":
            return self.otp_limit, self.otp_window
        if path.startswith("/api/v1/auth/resend-otp") and method == "POST":
            return self.otp_limit, self.otp_window
        if path.startswith("/api/v1/auth/register") and method == "POST":
            return self.auth_limit, self.auth_window
        if path.startswith("/api/v1/files/") and "download" in path and method == "GET":
            return self.download_limit, self.download_window
        if path.startswith("/api/v1/files/") and "download-token" in path and method == "POST":
            return self.otp_limit, self.otp_window
        if path.startswith("/api/v1/auth/"):
            return self.auth_limit, self.auth_window
        return self.default_limit, self.default_window

    def _is_blocked(self, key: str) -> float | None:
        now = time.time()
        block_until = self._blocked.get(key)
        if block_until and now < block_until:
            return block_until - now
        return None

    def _check_rate_limit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window
        timestamps = self._requests[key]
        self._requests[key] = [t for t in timestamps if t > cutoff]
        count = len(self._requests[key])
        if count >= limit:
            retry_after = int(self._requests[key][0] + window - now) + 1
            return False, max(retry_after, 1)
        self._requests[key].append(now)
        return True, 0

    def _get_progressive_delay(self, ip: str) -> int:
        violations = self._suspicious_patterns.get(ip, [])
        now = time.time()
        recent_violations = [t for t in violations if now - t < 3600]
        if len(recent_violations) >= 10:
            return 30
        elif len(recent_violations) >= 5:
            return 10
        return 0

    def _record_suspicious_activity(self, ip: str) -> None:
        self._suspicious_patterns[ip].append(time.time())

    def _detect_brute_force_pattern(self, ip: str, path: str) -> bool:
        key = f"bf:{ip}:{path}"
        now = time.time()
        timestamps = self._requests.get(key, [])
        recent = [t for t in timestamps if now - t < 60]
        if len(recent) >= 10:
            self._blocked[ip] = now + self.block_duration
            logger.warning(
                "Brute force detected from IP %s on %s, blocked for %ds",
                ip, path, self.block_duration
            )
            return True
        return False

    async def dispatch(self, request: Request, call_next: Callable):
        if request.url.path in ("/health", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        self._cleanup_old_entries()

        client_ip = self._get_client_ip(request)
        path = request.url.path
        method = request.method

        request_id = secrets.token_urlsafe(16)
        request.state.request_id = request_id

        if self._is_blocked(client_ip):
            remaining = int(self._blocked[client_ip] - time.time())
            logger.warning("Blocked IP %s (expires in %ds)", client_ip, remaining)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={
                    "Retry-After": str(remaining),
                    "X-RateLimit-Limit": "0",
                    "X-Request-ID": request_id,
                },
            )

        progressive_delay = self._get_progressive_delay(client_ip)
        if progressive_delay > 0:
            time.sleep(progressive_delay / 1000)

        if method == "POST" and self._detect_brute_force_pattern(client_ip, path):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={
                    "Retry-After": str(self.block_duration),
                    "X-RateLimit-Limit": "0",
                    "X-Request-ID": request_id,
                },
            )

        endpoint_limit, endpoint_window = self._classify_endpoint(path, method)
        ip_key = f"ip:{client_ip}"
        allowed, retry_after = self._check_rate_limit(ip_key, endpoint_limit, endpoint_window)

        if not allowed:
            ip_failures = self._requests.get(f"fail:{client_ip}", [])
            failure_count = len(ip_failures)
            self._requests[f"fail:{client_ip}"].append(time.time())

            self._record_suspicious_activity(client_ip)

            if failure_count >= self.block_threshold:
                self._blocked[client_ip] = time.time() + self.block_duration
                logger.warning(
                    "IP %s blocked for %ds after %d rate limit violations",
                    client_ip, self.block_duration, failure_count,
                )
            logger.warning(
                "Rate limit exceeded for IP %s on %s %s (limit: %d/%ds)",
                client_ip, method, path, endpoint_limit, endpoint_window,
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please try again later."},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(endpoint_limit),
                    "X-Request-ID": request_id,
                },
            )

        if f"fail:{client_ip}" in self._requests:
            self._requests.pop(f"fail:{client_ip}", None)

        response = await call_next(request)
        remaining = endpoint_limit - len(self._requests.get(ip_key, []))
        response.headers["X-RateLimit-Limit"] = str(endpoint_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-Request-ID"] = request_id
        return response
