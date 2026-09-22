from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds hardened security headers to all responses."""

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    CSP_DIRECTIVES = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "media-src 'none'; "
        "worker-src 'none'; "
        "child-src 'none'; "
        "manifest-src 'self'"
    )

    def __init__(self, app, csp_enabled: bool = True):
        super().__init__(app)
        self.csp_enabled = csp_enabled

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        for header, value in self.SECURITY_HEADERS.items():
            response.headers[header] = value

        if self.csp_enabled:
            response.headers["Content-Security-Policy"] = self.CSP_DIRECTIVES

        if "content-type" not in response.headers:
            response.headers["Content-Type"] = "application/json"

        try:
            del response.headers["server"]
        except (KeyError, Exception):
            pass
        try:
            del response.headers["x-powered-by"]
        except (KeyError, Exception):
            pass

        return response
