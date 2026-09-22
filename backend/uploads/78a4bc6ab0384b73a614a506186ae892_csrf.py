import hashlib
import hmac
import logging
import os
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

CSRF_TOKEN_EXPIRY = 3600
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """CSRF protection using double-submit cookie pattern with HMAC."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    EXEMPT_PATHS = {
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/verify-otp",
        "/api/v1/auth/resend-otp",
        "/api/v1/auth/refresh",
        "/api/v1/auth/enable-2fa",
        "/api/v1/auth/confirm-2fa",
        "/api/v1/auth/logout",
    }

    def __init__(self, app, secret_key: str | None = None):
        super().__init__(app)
        self.secret_key = secret_key or os.getenv("CSRF_SECRET_KEY", secrets.token_hex(32))
        self._token_store: dict[str, float] = {}

    def _cleanup_tokens(self) -> None:
        now = time.time()
        expired = [k for k, v in self._token_store.items() if now > v + CSRF_TOKEN_EXPIRY]
        for k in expired:
            del self._token_store[k]

    def generate_csrf_token(self, session_id: str | None = None) -> str:
        token = secrets.token_urlsafe(32)
        payload = f"{token}:{int(time.time())}"
        signature = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        self._token_store[token] = time.time()
        return f"{payload}:{signature}"

    def validate_csrf_token(self, token: str, session_id: str | None = None) -> bool:
        if not token or ":" not in token:
            return False

        parts = token.split(":")
        if len(parts) != 3:
            return False

        raw_token, timestamp_str, provided_signature = parts

        if raw_token not in self._token_store:
            return False

        stored_time = self._token_store[raw_token]
        if time.time() - stored_time > CSRF_TOKEN_EXPIRY:
            del self._token_store[raw_token]
            return False

        payload = f"{raw_token}:{timestamp_str}"
        expected_signature = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(provided_signature, expected_signature):
            logger.warning("CSRF token signature mismatch")
            return False

        return True

    def _is_same_origin(self, request: Request) -> bool:
        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")

        if not origin and not referer:
            return True

        host = request.headers.get("Host", "")

        if origin:
            try:
                parsed = urlparse(origin)
                if parsed.netloc != host:
                    return False
            except Exception:
                return False

        if referer:
            try:
                parsed = urlparse(referer)
                if parsed.netloc != host:
                    return False
            except Exception:
                return False

        return True

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next: Callable):
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        if request.method in self.SAFE_METHODS:
            response = await call_next(request)
            token = self.generate_csrf_token()
            response.set_cookie(
                CSRF_COOKIE_NAME,
                token,
                max_age=CSRF_TOKEN_EXPIRY,
                httponly=False,
                secure=False,
                samesite="lax",
            )
            return response

        if not self._is_same_origin(request):
            client_ip = self._get_client_ip(request)
            logger.warning(
                "CSRF: Cross-origin request blocked from %s to %s",
                client_ip, request.url.path
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Request blocked"},
            )

        csrf_token = request.headers.get(CSRF_HEADER_NAME)
        if not csrf_token:
            csrf_token = request.cookies.get(CSRF_COOKIE_NAME)

        if not csrf_token:
            client_ip = self._get_client_ip(request)
            logger.warning(
                "CSRF: Missing token from %s on %s",
                client_ip, request.url.path
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token required"},
            )

        session_id = request.cookies.get("session_id")
        if not self.validate_csrf_token(csrf_token, session_id):
            client_ip = self._get_client_ip(request)
            logger.warning(
                "CSRF: Invalid token from %s on %s",
                client_ip, request.url.path
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid CSRF token"},
            )

        self._cleanup_tokens()

        response = await call_next(request)

        new_token = self.generate_csrf_token()
        response.set_cookie(
            CSRF_COOKIE_NAME,
            new_token,
            max_age=CSRF_TOKEN_EXPIRY,
            httponly=False,
            secure=False,
            samesite="lax",
        )

        return response
