from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import init_db
from app.middleware import (
    CSRFProtectionMiddleware,
    InputSanitizationMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.routes import auth_router, users_router
from app.routes.files import router as files_router
from app.routes.security import router as security_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Starting {settings.APP_NAME}...")

    await init_db()

    try:
        from app.scripts.init_sample_files import initialize_sample_files
        await initialize_sample_files()
    except Exception as e:
        print(f"Warning: Could not initialize sample files: {e}")

    yield
    print("Shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Secure Two-Factor Authentication System API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "X-Request-ID"],
)

if settings.RATE_LIMIT_ENABLED:
    app.add_middleware(
        RateLimitMiddleware,
        default_limit=settings.RATE_LIMIT_DEFAULT,
        auth_limit=settings.RATE_LIMIT_AUTH,
        login_limit=settings.RATE_LIMIT_LOGIN,
        otp_limit=settings.RATE_LIMIT_OTP,
        block_threshold=settings.RATE_LIMIT_BLOCK_THRESHOLD,
        block_duration=settings.RATE_LIMIT_BLOCK_DURATION,
    )

app.add_middleware(CSRFProtectionMiddleware, secret_key=settings.SECRET_KEY)

if settings.SECURITY_HEADERS_ENABLED:
    app.add_middleware(SecurityHeadersMiddleware, csp_enabled=settings.CSP_ENABLED)

if settings.INPUT_SANITIZATION_ENABLED:
    app.add_middleware(InputSanitizationMiddleware)

app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(files_router, prefix="/api/v1")
app.include_router(security_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}
