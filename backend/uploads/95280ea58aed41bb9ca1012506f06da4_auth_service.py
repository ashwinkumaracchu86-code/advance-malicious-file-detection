import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.models.login_attempt import LoginAttempt
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest
from app.services.otp_service import OTPService
from app.services.security_audit import security_audit
from app.services.session_service import session_service
from app.services.sms_service import sms_service
from app.services.email_service import email_service

settings = get_settings()
logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

GENERIC_AUTH_ERROR = "Invalid credentials"
GENERIC_ACCOUNT_ERROR = "Invalid credentials"
GENERIC_REGISTRATION_MSG = "If this information is available, you will receive a confirmation."


class AuthService:
    @staticmethod
    async def register(db: AsyncSession, data: RegisterRequest) -> User:
        existing_user = await db.execute(
            select(User).where(
                or_(
                    User.username == data.username,
                    User.email == data.email,
                )
            )
        )
        duplicate = existing_user.scalar_one_or_none()

        if duplicate:
            if duplicate.username == data.username:
                raise ValueError("Username is already taken")
            if duplicate.email == data.email:
                raise ValueError("Email is already registered")
            raise ValueError("Account with this information already exists")

        if data.phone_number:
            existing_phone = await db.execute(
                select(User).where(User.phone_number == data.phone_number)
            )
            if existing_phone.scalar_one_or_none():
                raise ValueError("Phone number is already registered")

        user = User(
            username=data.username,
            email=data.email,
            full_name=data.full_name,
            phone_number=data.phone_number,
            password_hash=get_password_hash(data.password),
            account_status="active",
            is_verified=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def _find_user_by_identifier(db: AsyncSession, identifier: str) -> User | None:
        result = await db.execute(
            select(User).where(
                or_(
                    User.email == identifier,
                    User.username == identifier,
                )
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _log_login_attempt(
        db: AsyncSession,
        email: str,
        user_id: int | None,
        ip_address: str | None,
        user_agent: str | None,
        is_successful: bool,
        failure_reason: str | None = None,
    ) -> None:
        attempt = LoginAttempt(
            user_id=user_id,
            email=email,
            ip_address=ip_address or "unknown",
            user_agent=user_agent,
            is_successful=is_successful,
            failure_reason=failure_reason,
        )
        db.add(attempt)
        await db.commit()

    @staticmethod
    async def _check_account_lockout(db: AsyncSession, user: User) -> None:
        now = datetime.now(timezone.utc)

        if user.locked_until and user.locked_until > now:
            remaining = (user.locked_until - now).seconds // 60
            raise ValueError(f"Account is locked. Try again in {remaining} minutes.")

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            await db.commit()
            raise ValueError(
                f"Too many failed attempts. Account locked for {LOCKOUT_DURATION_MINUTES} minutes."
            )

    @staticmethod
    async def _reset_failed_attempts(db: AsyncSession, user: User) -> None:
        user.failed_login_attempts = 0
        user.last_failed_login_at = None
        user.locked_until = None
        await db.commit()

    @staticmethod
    async def _increment_failed_attempts(db: AsyncSession, user: User) -> None:
        user.failed_login_attempts += 1
        user.last_failed_login_at = datetime.now(timezone.utc)
        await db.commit()

    @staticmethod
    async def login(
        db: AsyncSession,
        data: LoginRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        user = await AuthService._find_user_by_identifier(db, data.identifier)

        if not user:
            await AuthService._log_login_attempt(
                db,
                email=data.identifier,
                user_id=None,
                ip_address=ip_address,
                user_agent=user_agent,
                is_successful=False,
                failure_reason="invalid_credentials",
            )
            await security_audit.log_login_failure(
                db, user_id=None, identifier=data.identifier, reason="invalid_credentials",
                ip_address=ip_address, user_agent=user_agent,
            )
            logger.warning("Login attempt with unknown identifier from %s", ip_address)
            raise ValueError(GENERIC_AUTH_ERROR)

        await AuthService._check_account_lockout(db, user)

        if user.account_status == "suspended":
            await AuthService._log_login_attempt(
                db,
                email=user.email,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                is_successful=False,
                failure_reason="account_disabled",
            )
            await security_audit.log_login_failure(
                db, user_id=user.id, identifier=user.email, reason="account_disabled",
                ip_address=ip_address, user_agent=user_agent,
            )
            raise ValueError(GENERIC_AUTH_ERROR)

        if user.account_status == "pending_verification":
            await AuthService._log_login_attempt(
                db,
                email=user.email,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                is_successful=False,
                failure_reason="account_not_verified",
            )
            await security_audit.log_login_failure(
                db, user_id=user.id, identifier=user.email, reason="account_not_verified",
                ip_address=ip_address, user_agent=user_agent,
            )
            raise ValueError(GENERIC_AUTH_ERROR)

        if not verify_password(data.password, user.password_hash):
            await AuthService._increment_failed_attempts(db, user)
            await AuthService._log_login_attempt(
                db,
                email=user.email,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                is_successful=False,
                failure_reason="invalid_credentials",
            )
            await security_audit.log_login_failure(
                db, user_id=user.id, identifier=user.email, reason="invalid_credentials",
                ip_address=ip_address, user_agent=user_agent,
            )
            logger.warning("Failed login for user %s from %s", user.username, ip_address)
            raise ValueError(GENERIC_AUTH_ERROR)

        await AuthService._reset_failed_attempts(db, user)

        if not user.phone_number:
            await AuthService._log_login_attempt(
                db,
                email=user.email,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                is_successful=True,
            )
            await security_audit.log_login_success(
                db, user_id=user.id, username=user.username,
                ip_address=ip_address, user_agent=user_agent, requires_2fa=False,
            )
            user.last_login_at = datetime.now(timezone.utc)
            user.last_login_ip = ip_address
            await db.commit()

            session_data = await session_service.create_session(
                db, user.id, ip_address, user_agent
            )

            return {
                "requires_2fa": False,
                "session_id": session_data["session_id"],
                "access_token": session_data["access_token"],
                "refresh_token": session_data["refresh_token"],
                "expires_in": session_data["expires_in"],
            }

        await OTPService.invalidate_user_otps(db, user.id, purpose="login")

        otp_code, otp_record = await OTPService.create_otp(
            db,
            user.id,
            purpose="login",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        masked_phone = (
            user.phone_number[:3] + "****" + user.phone_number[-2:]
            if user.phone_number and len(user.phone_number) > 5
            else None
        )
        masked_email = (
            user.email[:2] + "****@" + user.email.split("@")[1]
            if user.email
            else None
        )

        otp_channel = settings.OTP_CHANNEL
        delivery_success = False
        delivery_message = ""

        if otp_channel == "email" and user.email:
            delivery_success, delivery_message = await email_service.send_otp(
                user.email, otp_code, user.full_name or user.username
            )
        elif otp_channel == "sms" and user.phone_number:
            delivery_success, delivery_message = await sms_service.send_otp(
                user.phone_number, otp_code
            )
        else:
            if user.email:
                delivery_success, delivery_message = await email_service.send_otp(
                    user.email, otp_code, user.full_name or user.username
                )
            elif user.phone_number:
                delivery_success, delivery_message = await sms_service.send_otp(
                    user.phone_number, otp_code
                )
            else:
                delivery_success = False
                delivery_message = "No email or phone number configured"

        if not delivery_success:
            logger.error("Failed to deliver OTP to user %s: %s", user.id, delivery_message)

        await AuthService._log_login_attempt(
            db,
            email=user.email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            is_successful=True,
        )
        await security_audit.log_login_success(
            db, user_id=user.id, username=user.username,
            ip_address=ip_address, user_agent=user_agent, requires_2fa=True,
        )

        temp_token = create_access_token(
            {
                "sub": str(user.id),
                "purpose": "otp_verify",
                "otp_id": otp_record.id,
            },
            expires_delta=timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
        )

        logger.info("OTP sent to user %s via %s", user.id, otp_channel)

        dev_otp_code = None
        if not email_service.is_configured() and not sms_service.is_configured():
            dev_otp_code = otp_code

        result = {
            "requires_2fa": True,
            "message": delivery_message,
            "masked_phone": masked_phone,
            "masked_email": masked_email,
            "otp_channel": otp_channel,
            "temp_token": temp_token,
            "expires_in": settings.OTP_EXPIRE_MINUTES * 60,
        }
        if dev_otp_code:
            result["dev_otp"] = dev_otp_code

        return result

    @staticmethod
    async def resend_otp(
        db: AsyncSession,
        temp_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        payload = decode_token(temp_token)
        if not payload or payload.get("purpose") != "otp_verify":
            raise ValueError(GENERIC_AUTH_ERROR)

        user_id = int(payload["sub"])

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError(GENERIC_AUTH_ERROR)

        if not user.email and not user.phone_number:
            raise ValueError(GENERIC_AUTH_ERROR)

        rate_ok, rate_message = await OTPService.check_rate_limit(
            db, user_id, purpose="login"
        )
        if not rate_ok:
            if "Too many" in rate_message:
                raise ValueError(rate_message)

        otp_code, otp_record = await OTPService.create_otp(
            db,
            user.id,
            purpose="login",
            ip_address=ip_address,
            user_agent=user_agent,
        )

        masked_phone = (
            user.phone_number[:3] + "****" + user.phone_number[-2:]
            if user.phone_number and len(user.phone_number) > 5
            else None
        )
        masked_email = (
            user.email[:2] + "****@" + user.email.split("@")[1]
            if user.email
            else None
        )

        otp_channel = settings.OTP_CHANNEL
        delivery_success = False
        delivery_message = ""

        if otp_channel == "email" and user.email:
            delivery_success, delivery_message = await email_service.send_otp(
                user.email, otp_code, user.full_name or user.username
            )
        elif otp_channel == "sms" and user.phone_number:
            delivery_success, delivery_message = await sms_service.send_otp(
                user.phone_number, otp_code
            )
        else:
            if user.email:
                delivery_success, delivery_message = await email_service.send_otp(
                    user.email, otp_code, user.full_name or user.username
                )
            elif user.phone_number:
                delivery_success, delivery_message = await sms_service.send_otp(
                    user.phone_number, otp_code
                )

        if not delivery_success:
            logger.warning("OTP delivery failed for user %s, continuing anyway", user.id)

        temp_token = create_access_token(
            {
                "sub": str(user.id),
                "purpose": "otp_verify",
                "otp_id": otp_record.id,
            },
            expires_delta=timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
        )

        logger.info("OTP resent to user %s", user.id)

        remaining_requests = await OTPService.get_remaining_requests(
            db, user_id, purpose="login"
        )

        dev_otp_code = None
        if not email_service.is_configured() and not sms_service.is_configured():
            dev_otp_code = otp_code

        result = {
            "message": delivery_message,
            "temp_token": temp_token,
            "expires_in": settings.OTP_EXPIRE_MINUTES * 60,
            "remaining_requests": remaining_requests,
        }
        if dev_otp_code:
            result["dev_otp"] = dev_otp_code

        return result

    @staticmethod
    async def get_otp_status(
        db: AsyncSession, temp_token: str
    ) -> dict:
        payload = decode_token(temp_token)
        if not payload or payload.get("purpose") != "otp_verify":
            raise ValueError(GENERIC_AUTH_ERROR)

        user_id = int(payload["sub"])

        remaining_cooldown = await OTPService.get_remaining_cooldown(
            db, user_id, purpose="login"
        )
        remaining_requests = await OTPService.get_remaining_requests(
            db, user_id, purpose="login"
        )
        remaining_attempts = await OTPService.get_remaining_attempts(
            db, user_id, purpose="login"
        )

        return {
            "cooldown_seconds": remaining_cooldown,
            "remaining_requests": remaining_requests,
            "remaining_attempts": remaining_attempts,
            "expires_in": settings.OTP_EXPIRE_MINUTES * 60,
        }

    @staticmethod
    async def verify_otp_and_login(
        db: AsyncSession,
        temp_token: str,
        code: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict:
        payload = decode_token(temp_token)
        if not payload or payload.get("purpose") != "otp_verify":
            raise ValueError(GENERIC_AUTH_ERROR)

        user_id = int(payload["sub"])

        now = datetime.now(timezone.utc)
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError(GENERIC_AUTH_ERROR)

        if user.account_status != "active":
            raise ValueError(GENERIC_AUTH_ERROR)

        verified, otp_record, message = await OTPService.verify_otp(
            db, user_id, code, purpose="login", ip_address=ip_address
        )

        if not verified:
            remaining_attempts = await OTPService.get_remaining_attempts(
                db, user_id, purpose="login"
            )
            logger.warning(
                "Invalid OTP attempt for user %s from %s (remaining: %d)",
                user_id, ip_address, remaining_attempts
            )
            raise ValueError(GENERIC_AUTH_ERROR)

        user.last_login_at = now
        user.last_login_ip = ip_address
        await db.commit()

        await AuthService._log_login_attempt(
            db,
            email=user.email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            is_successful=True,
        )
        await security_audit.log_login_success(
            db, user_id=user.id, username=user.username,
            ip_address=ip_address, user_agent=user_agent, requires_2fa=False,
        )

        session_data = await session_service.create_session(
            db, user_id, ip_address, user_agent
        )

        logger.info("Successful login for user %s from %s", user.username, ip_address)

        return {
            "session_id": session_data["session_id"],
            "access_token": session_data["access_token"],
            "refresh_token": session_data["refresh_token"],
            "token_type": "bearer",
            "expires_in": session_data["expires_in"],
        }

    @staticmethod
    async def logout(
        db: AsyncSession,
        session_id: str,
    ) -> bool:
        return await session_service.invalidate_session(
            db, session_id, reason="logout"
        )

    @staticmethod
    async def logout_all_devices(
        db: AsyncSession,
        user_id: int,
    ) -> int:
        return await session_service.invalidate_all_user_sessions(
            db, user_id, reason="logout_all"
        )

    @staticmethod
    async def refresh_session(
        db: AsyncSession,
        session_id: str,
        refresh_token: str,
        ip_address: str | None = None,
    ) -> dict | None:
        return await session_service.refresh_session(
            db, session_id, refresh_token, ip_address
        )

    @staticmethod
    async def enable_2fa(db: AsyncSession, user_id: int, phone_number: str) -> str | None:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            return None

        otp_code, otp_record = await OTPService.create_otp(db, user.id, purpose="enable_2fa")
        await sms_service.send_otp(phone_number, otp_code)

        temp_token = create_access_token(
            {
                "sub": str(user.id),
                "purpose": "enable_2fa_verify",
                "otp_id": otp_record.id,
                "phone_number": phone_number,
            },
            expires_delta=timedelta(minutes=settings.OTP_EXPIRE_MINUTES),
        )
        return temp_token

    @staticmethod
    async def confirm_enable_2fa(
        db: AsyncSession, user_id: int, temp_token: str, code: str
    ) -> bool:
        payload = decode_token(temp_token)
        if not payload or payload.get("purpose") != "enable_2fa_verify":
            return False

        phone_number = payload.get("phone_number")
        if not phone_number:
            return False

        verified, _, _ = await OTPService.verify_otp(db, user_id, code, purpose="enable_2fa")
        if not verified:
            return False

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            return False

        user.phone_number = phone_number
        user.two_factor_enabled = True
        await db.commit()
        return True


auth_service = AuthService()
