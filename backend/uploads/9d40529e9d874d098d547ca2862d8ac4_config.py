from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Secure 2FA Authentication System"
    APP_ENV: str = "development"
    DEBUG: bool = True

    DATABASE_URL: str = "sqlite+aiosqlite:///./secure_2fa.db"

    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_PHONE_NUMBER: str = ""

    OTP_EXPIRE_MINUTES: int = 5
    OTP_LENGTH: int = 6
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_REQUESTS_PER_HOUR: int = 5
    OTP_MAX_ATTEMPTS: int = 3

    SESSION_EXPIRE_MINUTES: int = 30
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"

    REDIS_URL: str = "redis://localhost:6379/0"

    SMTP_SERVER: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = ""

    OTP_CHANNEL: str = "email"

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: int = 60
    RATE_LIMIT_AUTH: int = 10
    RATE_LIMIT_LOGIN: int = 5
    RATE_LIMIT_OTP: int = 8
    RATE_LIMIT_BLOCK_THRESHOLD: int = 50
    RATE_LIMIT_BLOCK_DURATION: int = 900

    SECURITY_HEADERS_ENABLED: bool = True
    CSP_ENABLED: bool = True
    INPUT_SANITIZATION_ENABLED: bool = True
    MAX_REQUEST_BODY_SIZE: int = 1_048_576

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]


@lru_cache
def get_settings() -> Settings:
    return Settings()
