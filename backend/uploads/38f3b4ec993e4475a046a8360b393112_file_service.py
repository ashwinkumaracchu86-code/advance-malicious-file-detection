import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.file import DownloadActivity, DownloadToken, ProtectedFile

settings = get_settings()
logger = logging.getLogger(__name__)

DOWNLOAD_TOKEN_EXPIRE_MINUTES = 5
SAMPLE_FILES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "sample_files")


class FileService:
    @staticmethod
    def generate_file_id() -> str:
        return secrets.token_urlsafe(16)

    @staticmethod
    def generate_download_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    async def get_active_files(
        db: AsyncSession,
        user_id: int | None = None,
    ) -> list[ProtectedFile]:
        result = await db.execute(
            select(ProtectedFile).where(
                ProtectedFile.is_active == True,
            ).order_by(ProtectedFile.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_file_by_id(
        db: AsyncSession,
        file_id: str,
    ) -> ProtectedFile | None:
        result = await db.execute(
            select(ProtectedFile).where(
                ProtectedFile.file_id == file_id,
                ProtectedFile.is_active == True,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create_download_token(
        db: AsyncSession,
        user_id: int,
        file_id: str,
    ) -> str:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(DownloadToken).where(
                DownloadToken.user_id == user_id,
                DownloadToken.file_id == file_id,
                DownloadToken.is_used == False,
                DownloadToken.expires_at > now,
            )
        )
        existing_token = result.scalar_one_or_none()

        if existing_token:
            existing_token.is_used = True
            existing_token.used_at = now
            await db.commit()

        token = FileService.generate_download_token()
        expires_at = now + timedelta(minutes=DOWNLOAD_TOKEN_EXPIRE_MINUTES)

        download_token = DownloadToken(
            token=token,
            user_id=user_id,
            file_id=file_id,
            expires_at=expires_at,
        )
        db.add(download_token)
        await db.commit()

        logger.info(
            "Download token created for user %s, file %s (expires: %s)",
            user_id, file_id, expires_at
        )

        return token

    @staticmethod
    async def validate_download_token(
        db: AsyncSession,
        token: str,
        user_id: int,
        file_id: str,
    ) -> tuple[bool, str]:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(DownloadToken).where(
                DownloadToken.token == token,
                DownloadToken.user_id == user_id,
                DownloadToken.file_id == file_id,
            )
        )
        download_token = result.scalar_one_or_none()

        if not download_token:
            return False, "Invalid download token"

        if download_token.is_used:
            logger.warning(
                "Reuse attempt of download token by user %s (token: %s)",
                user_id, token[:8]
            )
            return False, "Token already used"

        if download_token.expires_at <= now:
            return False, "Token expired"

        download_token.is_used = True
        download_token.used_at = now
        await db.commit()

        return True, "Token valid"

    @staticmethod
    async def log_download_activity(
        db: AsyncSession,
        user_id: int,
        file_id: str,
        ip_address: str,
        user_agent: str | None,
        status: str,
        failure_reason: str | None = None,
    ) -> None:
        activity = DownloadActivity(
            user_id=user_id,
            file_id=file_id,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            failure_reason=failure_reason,
        )
        db.add(activity)
        await db.commit()

    @staticmethod
    async def get_user_download_history(
        db: AsyncSession,
        user_id: int,
        limit: int = 10,
    ) -> list[DownloadActivity]:
        result = await db.execute(
            select(DownloadActivity)
            .where(DownloadActivity.user_id == user_id)
            .order_by(DownloadActivity.downloaded_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_download_stats(
        db: AsyncSession,
        file_id: str,
    ) -> dict:
        from sqlalchemy import func

        total_result = await db.execute(
            select(func.count(DownloadActivity.id))
            .where(
                DownloadActivity.file_id == file_id,
                DownloadActivity.status == "success",
            )
        )
        total_downloads = total_result.scalar() or 0

        unique_result = await db.execute(
            select(func.count(func.distinct(DownloadActivity.user_id)))
            .where(
                DownloadActivity.file_id == file_id,
                DownloadActivity.status == "success",
            )
        )
        unique_users = unique_result.scalar() or 0

        return {
            "total_downloads": total_downloads,
            "unique_users": unique_users,
        }

    @staticmethod
    def get_sample_files_dir() -> str:
        return os.path.abspath(SAMPLE_FILES_DIR)


file_service = FileService()
