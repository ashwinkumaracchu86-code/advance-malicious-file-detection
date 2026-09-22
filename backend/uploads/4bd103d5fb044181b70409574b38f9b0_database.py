from collections.abc import AsyncGenerator
import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

db_url = settings.DATABASE_URL
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_async_engine(db_url, echo=settings.DEBUG, connect_args=connect_args)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create all tables (for SQLite development mode)."""
    async with engine.begin() as conn:
        from app.models.user import User
        from app.models.otp import OTPCode
        from app.models.session import UserSession
        from app.models.login_attempt import LoginAttempt
        from app.models.audit_log import SecurityAuditLog
        from app.models.file import ProtectedFile, DownloadToken, DownloadActivity
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        from app.core.security import get_password_hash

        result = await session.execute(
            select(User).where(User.username == "admin")
        )
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                email="admin@example.com",
                full_name="Administrator",
                password_hash=get_password_hash("gpt"),
                account_status="active",
                is_verified=True,
                is_active=True,
            )
            session.add(admin)
            await session.commit()
            print("Default admin user created (username: admin, password: gpt)")
