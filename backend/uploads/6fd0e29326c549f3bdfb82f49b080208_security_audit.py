import json
import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import SecurityAuditLog

logger = logging.getLogger(__name__)

SENSITIVE_FIELDS = {
    "password", "password_hash", "otp_code", "otp", "token",
    "access_token", "refresh_token", "secret", "api_key",
    "authorization", "credit_card", "ssn", "secret_key",
}


def sanitize_metadata(data: dict | None) -> dict | None:
    if not data:
        return None
    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in SENSITIVE_FIELDS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_metadata(value)
        else:
            sanitized[key] = value
    return sanitized


class SecurityAuditService:
    """Lightweight helper to persist security events to the audit log table."""

    @staticmethod
    async def log(
        db: AsyncSession,
        *,
        event_type: str,
        event_description: str,
        severity: str = "info",
        user_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        old_value: dict | None = None,
        new_value: dict | None = None,
        metadata: dict | None = None,
    ) -> None:
        try:
            sanitized_metadata = sanitize_metadata(metadata)
            sanitized_old = sanitize_metadata(old_value)
            sanitized_new = sanitize_metadata(new_value)

            audit = SecurityAuditLog(
                user_id=user_id,
                event_type=event_type,
                event_description=event_description,
                severity=severity,
                ip_address=ip_address,
                user_agent=user_agent,
                resource_type=resource_type,
                resource_id=resource_id,
                old_value=json.dumps(sanitized_old) if sanitized_old else None,
                new_value=json.dumps(sanitized_new) if sanitized_new else None,
                metadata_json=json.dumps(sanitized_metadata) if sanitized_metadata else None,
            )
            db.add(audit)
            await db.commit()
        except Exception:
            logger.exception("Failed to write security audit event: %s", event_type)

    @staticmethod
    async def log_registration(
        db: AsyncSession,
        *,
        user_id: int,
        username: str,
        email: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="user_registration",
            event_description=f"New user registered: {username}",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="user",
            resource_id=str(user_id),
            new_value={"username": username, "email": email},
        )

    @staticmethod
    async def log_login_success(
        db: AsyncSession,
        *,
        user_id: int,
        username: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        requires_2fa: bool = False,
    ) -> None:
        description = f"Login successful (2FA required: {requires_2fa})"
        await SecurityAuditService.log(
            db,
            event_type="login_success",
            event_description=description,
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="authentication",
            metadata={"username": username, "requires_2fa": requires_2fa},
        )

    @staticmethod
    async def log_login_failure(
        db: AsyncSession,
        *,
        user_id: int | None,
        identifier: str,
        reason: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="login_failure",
            event_description=f"Login failed: {reason}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="authentication",
            metadata={"identifier": identifier, "reason": reason},
        )

    @staticmethod
    async def log_otp_generated(
        db: AsyncSession,
        *,
        user_id: int,
        purpose: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="otp_generated",
            event_description=f"OTP generated for: {purpose}",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="otp",
            metadata={"purpose": purpose},
        )

    @staticmethod
    async def log_otp_success(
        db: AsyncSession,
        *,
        user_id: int,
        purpose: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="otp_success",
            event_description=f"OTP verified successfully for: {purpose}",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="otp",
            metadata={"purpose": purpose},
        )

    @staticmethod
    async def log_otp_failure(
        db: AsyncSession,
        *,
        user_id: int,
        purpose: str,
        reason: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="otp_failure",
            event_description=f"OTP verification failed: {reason}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="otp",
            metadata={"purpose": purpose, "reason": reason},
        )

    @staticmethod
    async def log_otp_resend(
        db: AsyncSession,
        *,
        user_id: int,
        purpose: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="otp_resend",
            event_description=f"OTP resent for: {purpose}",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="otp",
            metadata={"purpose": purpose},
        )

    @staticmethod
    async def log_account_lockout(
        db: AsyncSession,
        *,
        user_id: int,
        reason: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="account_lockout",
            event_description=f"Account locked: {reason}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(user_id),
            metadata={"reason": reason},
        )

    @staticmethod
    async def log_rate_limit_hit(
        db: AsyncSession,
        *,
        ip_address: str,
        path: str,
        user_id: int | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="rate_limit_hit",
            event_description=f"Rate limit exceeded on {path}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="endpoint",
            resource_id=path,
        )

    @staticmethod
    async def log_file_download_success(
        db: AsyncSession,
        *,
        user_id: int,
        file_id: str,
        filename: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="file_download_success",
            event_description=f"File downloaded: {filename}",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="file",
            resource_id=file_id,
            metadata={"filename": filename},
        )

    @staticmethod
    async def log_file_download_failure(
        db: AsyncSession,
        *,
        user_id: int,
        file_id: str,
        reason: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="file_download_failure",
            event_description=f"File download failed: {reason}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="file",
            resource_id=file_id,
            metadata={"reason": reason},
        )

    @staticmethod
    async def log_logout(
        db: AsyncSession,
        *,
        user_id: int,
        session_id: str,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="logout",
            event_description="User logged out",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="session",
            resource_id=session_id[:16],
        )

    @staticmethod
    async def log_session_anomaly(
        db: AsyncSession,
        *,
        user_id: int,
        session_id: str,
        anomaly_type: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: dict | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="session_anomaly",
            event_description=f"Session anomaly: {anomaly_type}",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            resource_type="session",
            resource_id=session_id[:16],
            metadata=details,
        )

    @staticmethod
    async def log_password_change(
        db: AsyncSession,
        *,
        user_id: int,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="password_change",
            event_description="Password changed",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(user_id),
        )

    @staticmethod
    async def log_2fa_enabled(
        db: AsyncSession,
        *,
        user_id: int,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="2fa_enabled",
            event_description="Two-factor authentication enabled",
            severity="info",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(user_id),
        )

    @staticmethod
    async def log_2fa_disabled(
        db: AsyncSession,
        *,
        user_id: int,
        ip_address: str | None = None,
    ) -> None:
        await SecurityAuditService.log(
            db,
            event_type="2fa_disabled",
            event_description="Two-factor authentication disabled",
            severity="warning",
            user_id=user_id,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(user_id),
        )

    @staticmethod
    async def get_user_activity(
        db: AsyncSession,
        user_id: int,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SecurityAuditLog]:
        result = await db.execute(
            select(SecurityAuditLog)
            .where(SecurityAuditLog.user_id == user_id)
            .order_by(SecurityAuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_all_activity(
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        event_type: str | None = None,
        severity: str | None = None,
    ) -> list[SecurityAuditLog]:
        query = select(SecurityAuditLog)

        if event_type:
            query = query.where(SecurityAuditLog.event_type == event_type)
        if severity:
            query = query.where(SecurityAuditLog.severity == severity)

        result = await db.execute(
            query.order_by(SecurityAuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_activity_count(
        db: AsyncSession,
        user_id: int | None = None,
        event_type: str | None = None,
    ) -> int:
        query = select(func.count(SecurityAuditLog.id))

        if user_id:
            query = query.where(SecurityAuditLog.user_id == user_id)
        if event_type:
            query = query.where(SecurityAuditLog.event_type == event_type)

        result = await db.execute(query)
        return result.scalar() or 0

    @staticmethod
    async def get_security_stats(
        db: AsyncSession,
        user_id: int | None = None,
    ) -> dict:
        now = datetime.now(timezone.utc)

        from datetime import timedelta
        twenty_four_hours_ago = now - timedelta(hours=24)
        seven_days_ago = now - timedelta(days=7)

        base_query = select(func.count(SecurityAuditLog.id))
        if user_id:
            base_query = base_query.where(SecurityAuditLog.user_id == user_id)

        total_result = await db.execute(base_query)
        total_events = total_result.scalar() or 0

        recent_result = await db.execute(
            base_query.where(SecurityAuditLog.created_at > twenty_four_hours_ago)
        )
        recent_events = recent_result.scalar() or 0

        failed_logins_result = await db.execute(
            base_query.where(
                SecurityAuditLog.event_type == "login_failure",
                SecurityAuditLog.created_at > seven_days_ago,
            )
        )
        failed_logins = failed_logins_result.scalar() or 0

        successful_logins_result = await db.execute(
            base_query.where(
                SecurityAuditLog.event_type == "login_success",
                SecurityAuditLog.created_at > seven_days_ago,
            )
        )
        successful_logins = successful_logins_result.scalar() or 0

        warnings_result = await db.execute(
            base_query.where(
                SecurityAuditLog.severity == "warning",
                SecurityAuditLog.created_at > seven_days_ago,
            )
        )
        warnings = warnings_result.scalar() or 0

        return {
            "total_events": total_events,
            "recent_events_24h": recent_events,
            "failed_logins_7d": failed_logins,
            "successful_logins_7d": successful_logins,
            "warnings_7d": warnings,
        }


security_audit = SecurityAuditService()
