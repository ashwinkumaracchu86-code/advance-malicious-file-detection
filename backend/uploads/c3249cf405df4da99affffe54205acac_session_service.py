import logging
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.models.session import UserSession
from app.services.security_audit import security_audit

settings = get_settings()
logger = logging.getLogger(__name__)


class SessionService:
    @staticmethod
    def generate_session_id() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_token(token: str) -> str:
        from app.core.security import hash_token as _hash_token
        return _hash_token(token)

    @staticmethod
    async def create_session(
        db: AsyncSession,
        user_id: int,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        await SessionService.invalidate_all_user_sessions(db, user_id, reason="new_session")

        session_id = SessionService.generate_session_id()
        access_token = create_access_token(
            {"sub": str(user_id), "session_id": session_id, "type": "access"}
        )
        refresh_token = create_refresh_token(
            {"sub": str(user_id), "session_id": session_id, "type": "refresh"}
        )

        access_token_hash = SessionService.hash_token(access_token)
        refresh_token_hash = SessionService.hash_token(refresh_token)

        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.SESSION_EXPIRE_MINUTES
        )

        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            token_hash=access_token_hash,
            refresh_token_hash=refresh_token_hash,
            ip_address=ip_address or "unknown",
            user_agent=user_agent,
            expires_at=expires_at,
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)

        logger.info("Session created for user %s (session: %s)", user_id, session_id[:8])

        return {
            "session_id": session_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": settings.SESSION_EXPIRE_MINUTES * 60,
        }

    @staticmethod
    async def validate_session(
        db: AsyncSession,
        session_id: str,
        token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[bool, UserSession | None]:
        now = datetime.now(timezone.utc)

        result = await db.execute(
            select(UserSession).where(
                UserSession.session_id == session_id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            return False, None

        token_hash = SessionService.hash_token(token)
        if session.token_hash != token_hash:
            logger.warning(
                "Invalid token for session %s (user: %s)",
                session_id[:8], session.user_id
            )
            session.is_active = False
            session.revoked_at = now
            session.revoke_reason = "invalid_token"
            await db.commit()
            return False, None

        if ip_address and session.ip_address and session.ip_address != ip_address:
            logger.warning(
                "IP mismatch for session %s: expected %s, got %s (user: %s)",
                session_id[:8], session.ip_address, ip_address, session.user_id,
            )
            await security_audit.log_session_anomaly(
                db,
                user_id=session.user_id,
                session_id=session_id,
                anomaly_type="ip_address_changed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"original_ip": session.ip_address, "new_ip": ip_address},
            )
            session.ip_address = ip_address

        if user_agent and session.user_agent and session.user_agent != user_agent:
            logger.warning(
                "User-Agent mismatch for session %s (user: %s)",
                session_id[:8], session.user_id,
            )
            await security_audit.log_session_anomaly(
                db,
                user_id=session.user_id,
                session_id=session_id,
                anomaly_type="user_agent_changed",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"original_ua": session.user_agent[:200], "new_ua": user_agent[:200]},
            )
            session.user_agent = user_agent

        session.last_activity_at = now
        await db.commit()

        return True, session

    @staticmethod
    async def refresh_session(
        db: AsyncSession,
        session_id: str,
        refresh_token: str,
        ip_address: str | None = None,
    ) -> dict | None:
        now = datetime.now(timezone.utc)

        result = await db.execute(
            select(UserSession).where(
                UserSession.session_id == session_id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            return None

        refresh_token_hash = SessionService.hash_token(refresh_token)
        if session.refresh_token_hash != refresh_token_hash:
            logger.warning(
                "Invalid refresh token for session %s (user: %s)",
                session_id[:8], session.user_id
            )
            session.is_active = False
            session.revoked_at = now
            session.revoke_reason = "invalid_refresh_token"
            await db.commit()
            return None

        new_access_token = create_access_token(
            {"sub": str(session.user_id), "session_id": session_id, "type": "access"}
        )
        new_refresh_token = create_refresh_token(
            {"sub": str(session.user_id), "session_id": session_id, "type": "refresh"}
        )

        session.token_hash = SessionService.hash_token(new_access_token)
        session.refresh_token_hash = SessionService.hash_token(new_refresh_token)
        session.last_activity_at = now
        session.ip_address = ip_address or session.ip_address
        session.expires_at = now + timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)

        await db.commit()

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "expires_in": settings.SESSION_EXPIRE_MINUTES * 60,
        }

    @staticmethod
    async def invalidate_session(
        db: AsyncSession,
        session_id: str,
        reason: str = "logout",
    ) -> bool:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(UserSession).where(
                UserSession.session_id == session_id,
                UserSession.is_active == True,
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            return False

        session.is_active = False
        session.revoked_at = now
        session.revoke_reason = reason
        await db.commit()

        logger.info("Session invalidated: %s (reason: %s)", session_id[:8], reason)
        return True

    @staticmethod
    async def invalidate_all_user_sessions(
        db: AsyncSession,
        user_id: int,
        reason: str = "security",
    ) -> int:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
            )
        )
        sessions = result.scalars().all()

        count = 0
        for session in sessions:
            session.is_active = False
            session.revoked_at = now
            session.revoke_reason = reason
            count += 1

        if count > 0:
            await db.commit()
            logger.info("Invalidated %d sessions for user %s", count, user_id)

        return count

    @staticmethod
    async def get_user_sessions(
        db: AsyncSession,
        user_id: int,
    ) -> list[UserSession]:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(UserSession).where(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            ).order_by(UserSession.last_activity_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def cleanup_expired_sessions(db: AsyncSession) -> int:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(UserSession).where(
                UserSession.is_active == True,
                UserSession.expires_at <= now,
            )
        )
        sessions = result.scalars().all()

        count = 0
        for session in sessions:
            session.is_active = False
            session.revoked_at = now
            session.revoke_reason = "expired"
            count += 1

        if count > 0:
            await db.commit()
            logger.info("Cleaned up %d expired sessions", count)

        return count


session_service = SessionService()
