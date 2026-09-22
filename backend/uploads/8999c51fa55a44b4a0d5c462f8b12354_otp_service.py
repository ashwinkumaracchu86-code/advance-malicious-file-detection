import logging
import secrets
import string
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import get_password_hash, verify_password
from app.models.otp import OTPCode

settings = get_settings()
logger = logging.getLogger(__name__)

OTP_MAX_TOTAL_FAILURES = 10
OTP_LOCKOUT_MINUTES = 30


class OTPService:
    @staticmethod
    def generate_otp(length: int | None = None) -> str:
        otp_length = length or settings.OTP_LENGTH
        return "".join(secrets.choice(string.digits) for _ in range(otp_length))

    @staticmethod
    def hash_otp(otp_code: str) -> str:
        return get_password_hash(otp_code)

    @staticmethod
    async def check_rate_limit(db: AsyncSession, user_id: int, purpose: str) -> tuple[bool, str]:
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.created_at > one_hour_ago,
            )
        )
        recent_otps = result.scalars().all()

        if len(recent_otps) >= settings.OTP_MAX_REQUESTS_PER_HOUR:
            return False, "Too many OTP requests. Please try again later."

        if recent_otps:
            latest_otp = max(recent_otps, key=lambda x: x.created_at)
            cooldown_end = latest_otp.created_at + timedelta(
                seconds=settings.OTP_RESEND_COOLDOWN_SECONDS
            )
            if now < cooldown_end:
                remaining = (cooldown_end - now).seconds
                return False, f"Please wait {remaining} seconds before requesting a new code."

        return True, ""

    @staticmethod
    async def check_otp_lockout(db: AsyncSession, user_id: int, purpose: str) -> tuple[bool, str]:
        now = datetime.now(timezone.utc)
        thirty_mins_ago = now - timedelta(minutes=OTP_LOCKOUT_MINUTES)

        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.created_at > thirty_mins_ago,
            )
        )
        recent_otps = result.scalars().all()

        total_failures = sum(otp.attempts for otp in recent_otps)

        if total_failures >= OTP_MAX_TOTAL_FAILURES:
            return False, "Too many failed attempts. Please try again later."

        return True, ""

    @staticmethod
    async def create_otp(
        db: AsyncSession,
        user_id: int,
        purpose: str = "login",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, OTPCode]:
        await OTPService.invalidate_user_otps(db, user_id, purpose)

        code = OTPService.generate_otp()
        code_hash = OTPService.hash_otp(code)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

        otp = OTPCode(
            user_id=user_id,
            code_hash=code_hash,
            purpose=purpose,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )
        db.add(otp)
        await db.commit()
        await db.refresh(otp)
        return code, otp

    @staticmethod
    async def verify_otp(
        db: AsyncSession, user_id: int, code: str, purpose: str = "login",
        ip_address: str | None = None,
    ) -> tuple[bool, OTPCode | None, str]:
        now = datetime.now(timezone.utc)

        lockout_ok, lockout_msg = await OTPService.check_otp_lockout(db, user_id, purpose)
        if not lockout_ok:
            return False, None, lockout_msg

        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.is_used == False,
                OTPCode.expires_at > now,
            )
            .order_by(OTPCode.created_at.desc())
            .limit(5)
        )
        otps = result.scalars().all()

        if not otps:
            return False, None, "No active OTP found. Please request a new code."

        for otp in otps:
            if otp.attempts >= otp.max_attempts:
                otp.is_used = True
                otp.used_at = now
                await db.commit()
                continue

            if verify_password(code, otp.code_hash):
                otp.is_used = True
                otp.used_at = now
                otp.attempts += 1
                await db.commit()

                logger.info(
                    "OTP verified for user %s (otp_id: %s, ip: %s)",
                    user_id, otp.id, ip_address
                )
                return True, otp, "OTP verified successfully"

            otp.attempts += 1
            if otp.attempts >= otp.max_attempts:
                otp.is_used = True
                otp.used_at = now

            logger.warning(
                "Invalid OTP attempt for user %s (otp_id: %s, attempts: %d/%d, ip: %s)",
                user_id, otp.id, otp.attempts, otp.max_attempts, ip_address
            )

        await db.commit()
        return False, None, "Invalid verification code"

    @staticmethod
    async def invalidate_user_otps(
        db: AsyncSession, user_id: int, purpose: str = "login"
    ) -> None:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(OTPCode).where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.is_used == False,
            )
        )
        otps = result.scalars().all()
        for otp in otps:
            otp.is_used = True
            otp.used_at = now
        await db.commit()

    @staticmethod
    async def get_remaining_cooldown(
        db: AsyncSession, user_id: int, purpose: str
    ) -> int:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
            )
            .order_by(OTPCode.created_at.desc())
            .limit(1)
        )
        latest_otp = result.scalar_one_or_none()

        if not latest_otp:
            return 0

        cooldown_end = latest_otp.created_at + timedelta(
            seconds=settings.OTP_RESEND_COOLDOWN_SECONDS
        )
        if now < cooldown_end:
            return (cooldown_end - now).seconds
        return 0

    @staticmethod
    async def get_remaining_requests(
        db: AsyncSession, user_id: int, purpose: str
    ) -> int:
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.created_at > one_hour_ago,
            )
        )
        recent_otps = result.scalars().all()

        return max(0, settings.OTP_MAX_REQUESTS_PER_HOUR - len(recent_otps))

    @staticmethod
    async def get_remaining_attempts(
        db: AsyncSession, user_id: int, purpose: str
    ) -> int:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user_id,
                OTPCode.purpose == purpose,
                OTPCode.is_used == False,
                OTPCode.expires_at > now,
            )
            .order_by(OTPCode.created_at.desc())
            .limit(1)
        )
        active_otp = result.scalar_one_or_none()

        if not active_otp:
            return 0

        return max(0, active_otp.max_attempts - active_otp.attempts)
