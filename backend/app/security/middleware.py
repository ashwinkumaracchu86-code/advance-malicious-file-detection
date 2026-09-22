import time
import logging
import os
from typing import Dict, Optional
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
).split(",")

MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

BLOCKED_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsh", ".wsf",
    ".ps1", ".psm1", ".psd1", ".psc1",
    ".hta", ".cpl", ".msc", ".reg", ".inf",
    ".dll", ".sys", ".drv", ".ocx",
}

ALLOWED_UPLOAD_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".html", ".css", ".js",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".mp3", ".mp4", ".wav", ".flac", ".ogg",
    ".py", ".java", ".c", ".cpp", ".h", ".go", ".rs",
    ".eml", ".msg",
}


class LoginAttemptTracker:
    def __init__(self):
        self._attempts: Dict[str, list] = defaultdict(list)
        self._lockouts: Dict[str, datetime] = {}
        self._max_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self._lockout_minutes = int(os.getenv("LOCKOUT_MINUTES", "15"))
        self._window_minutes = int(os.getenv("LOGIN_WINDOW_MINUTES", "5"))

    def _cleanup_old_attempts(self, ip: str):
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self._window_minutes)
        self._attempts[ip] = [
            t for t in self._attempts[ip] if t > cutoff
        ]

    def record_failed_attempt(self, ip: str) -> bool:
        self._cleanup_old_attempts(ip)
        self._attempts[ip].append(datetime.now(timezone.utc))

        if len(self._attempts[ip]) >= self._max_attempts:
            self._lockouts[ip] = datetime.now(timezone.utc)
            logger.warning(f"Account locked out for IP: {ip} after {self._max_attempts} failed attempts")
            return True
        return False

    def is_locked_out(self, ip: str) -> bool:
        if ip not in self._lockouts:
            return False
        lockout_time = self._lockouts[ip]
        if datetime.now(timezone.utc) - lockout_time > timedelta(minutes=self._lockout_minutes):
            del self._lockouts[ip]
            self._attempts[ip] = []
            return False
        return True

    def clear_attempts(self, ip: str):
        self._attempts.pop(ip, None)
        self._lockouts.pop(ip, None)

    def get_remaining_attempts(self, ip: str) -> int:
        self._cleanup_old_attempts(ip)
        return max(0, self._max_attempts - len(self._attempts[ip]))


login_tracker = LoginAttemptTracker()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: Dict[str, list] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        now = time.time()
        cutoff = now - 60

        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if t > cutoff
        ]

        if len(self._requests[client_ip]) >= self.requests_per_minute:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Please try again later."},
                headers={"Retry-After": "60"},
            )

        self._requests[client_ip].append(now)
        response = await call_next(request)
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"

        response = await call_next(request)

        duration = time.time() - start_time
        status_code = response.status_code

        log_level = logging.WARNING if status_code >= 400 else logging.INFO
        logger.log(
            log_level,
            f"{request.method} {request.url.path} - {status_code} - {duration:.3f}s - {client_ip}"
        )

        return response


class UploadSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and "/upload" in request.url.path:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_UPLOAD_SIZE_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "detail": f"File too large. Maximum size is {MAX_UPLOAD_SIZE_MB}MB."
                    },
                )

        response = await call_next(request)
        return response
