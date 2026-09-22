import json
import re
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_NULL_BYTE_RE = re.compile(r"\x00")
_SCRIPT_TAG_RE = re.compile(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r"\bon\w+\s*=", re.IGNORECASE)
_JS_URI_RE = re.compile(r"javascript\s*:", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_PATTERNS_RE = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe", re.IGNORECASE),
    re.compile(r"<object", re.IGNORECASE),
    re.compile(r"<embed", re.IGNORECASE),
    re.compile(r"<form", re.IGNORECASE),
    re.compile(r"<svg\s+onload", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"expression\s*\(", re.IGNORECASE),
    re.compile(r"url\s*\(\s*['\"]?javascript:", re.IGNORECASE),
    re.compile(r"<\s*\/?\s*(body|div|img|input|a|button|link|meta|style|table|td|tr|th|thead|tbody|tfoot|ul|ol|li|p|span|b|i|u|strong|em|h[1-6])\b", re.IGNORECASE),
]

SQL_INJECTION_PATTERNS = [
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|FETCH|DECLARE|TRUNCATE)\b)", re.IGNORECASE),
    re.compile(r"(--|#|\/\*|\*\/)", re.IGNORECASE),
    re.compile(r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    re.compile(r"('|\")(;|\s*(OR|AND)\s*)", re.IGNORECASE),
    re.compile(r"(CHAR\(|CONCAT\(|0x[0-9a-f]+)", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"%252e%252e", re.IGNORECASE),
]


def sanitize_string(value: str) -> str:
    if not isinstance(value, str):
        return value
    value = _NULL_BYTE_RE.sub("", value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    lines = value.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped == "--":
            continue
        is_xss = any(p.search(stripped) for p in _PATTERNS_RE)
        if is_xss:
            stripped = _SCRIPT_TAG_RE.sub("", stripped)
            stripped = _EVENT_HANDLER_RE.sub("", stripped)
            stripped = _JS_URI_RE.sub("", stripped)
            stripped = _TAG_RE.sub("", stripped)
        cleaned_lines.append(stripped)
    return "\n".join(cleaned_lines)


def check_sql_injection(value: str) -> bool:
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(value):
            return True
    return False


def check_path_traversal(value: str) -> bool:
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(value):
            return True
    return False


def sanitize_value(value):
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    return value


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """Sanitizes request body inputs against XSS, SQL injection, and path traversal attacks."""

    SANITIZE_CONTENT_TYPES = {"application/json", "application/x-www-form-urlencoded"}
    EXEMPT_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/verify-otp",
        "/api/v1/auth/resend-otp",
        "/api/v1/auth/enable-2fa",
        "/api/v1/auth/confirm-2fa",
    }

    async def dispatch(self, request: Request, call_next: Callable):
        content_type = request.headers.get("content-type", "")

        if request.method in ("POST", "PUT", "PATCH"):
            if any(ct in content_type for ct in self.SANITIZE_CONTENT_TYPES):
                try:
                    body = await request.body()
                    if body:
                        text = body.decode("utf-8", errors="replace")
                        if len(text) > 1_048_576:
                            return JSONResponse(
                                status_code=413,
                                content={"detail": "Request body too large"},
                            )
                        if "application/json" in content_type:
                            if request.url.path not in self.EXEMPT_PATHS:
                                data = json.loads(text)
                                sanitized = sanitize_value(data)
                                sanitized_body = json.dumps(sanitized).encode("utf-8")
                                request._body = sanitized_body
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        query_string = request.url.query
        if query_string:
            if check_sql_injection(query_string):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid request parameters"},
                )
            if check_path_traversal(query_string):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid request path"},
                )

        path = request.url.path
        if check_path_traversal(path):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid request path"},
            )

        return await call_next(request)
