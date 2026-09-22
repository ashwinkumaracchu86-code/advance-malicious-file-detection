import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User
from app.services.file_service import file_service
from app.services.session_service import session_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["Files"])


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    session_id = request.cookies.get("session_id")
    access_token = request.cookies.get("access_token")

    if not session_id or not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = int(payload["sub"])

    valid, session = await session_service.validate_session(
        db, session_id, access_token
    )

    if not valid or not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    if user.account_status != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not active",
        )

    return user


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")


class FileInfoResponse(BaseModel):
    file_id: str
    filename: str
    description: Optional[str] = None
    file_size: int
    mime_type: str
    created_at: datetime
    download_count: int = 0


class DownloadTokenResponse(BaseModel):
    token: str
    expires_in: int
    file_id: str


class DownloadHistoryResponse(BaseModel):
    file_id: str
    filename: str
    status: str
    downloaded_at: datetime
    ip_address: str


@router.get("", response_model=list[FileInfoResponse])
async def list_files(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    files = await file_service.get_active_files(db, user.id)

    result = []
    for file in files:
        stats = await file_service.get_download_stats(db, file.file_id)
        result.append(FileInfoResponse(
            file_id=file.file_id,
            filename=file.original_filename,
            description=file.description,
            file_size=file.file_size,
            mime_type=file.mime_type,
            created_at=file.created_at,
            download_count=stats["total_downloads"],
        ))

    return result


@router.get("/{file_id}", response_model=FileInfoResponse)
async def get_file_info(
    file_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    file = await file_service.get_file_by_id(db, file_id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    stats = await file_service.get_download_stats(db, file.file_id)

    return FileInfoResponse(
        file_id=file.file_id,
        filename=file.original_filename,
        description=file.description,
        file_size=file.file_size,
        mime_type=file.mime_type,
        created_at=file.created_at,
        download_count=stats["total_downloads"],
    )


@router.post("/{file_id}/download-token", response_model=DownloadTokenResponse)
async def request_download_token(
    file_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    file = await file_service.get_file_by_id(db, file_id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    if file.requires_2fa and not user.two_factor_enabled:
        await file_service.log_download_activity(
            db, user.id, file_id, "0.0.0.0", None,
            "denied", "2fa_required"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Two-factor authentication required to download this file",
        )

    token = await file_service.create_download_token(db, user.id, file_id)

    logger.info(
        "Download token issued for user %s (file: %s)",
        user.username, file.original_filename
    )

    return DownloadTokenResponse(
        token=token,
        expires_in=300,
        file_id=file_id,
    )


@router.get("/{file_id}/download/{token}")
async def download_file(
    file_id: str,
    token: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    file = await file_service.get_file_by_id(db, file_id)
    if not file:
        await file_service.log_download_activity(
            db, user.id, file_id, ip_address, user_agent,
            "failed", "file_not_found"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    valid, message = await file_service.validate_download_token(
        db, token, user.id, file_id
    )

    if not valid:
        await file_service.log_download_activity(
            db, user.id, file_id, ip_address, user_agent,
            "denied", message
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=message,
        )

    file_path = os.path.abspath(file.storage_path)
    sample_dir = os.path.abspath(file_service.get_sample_files_dir())

    if not file_path.startswith(sample_dir):
        await file_service.log_download_activity(
            db, user.id, file_id, ip_address, user_agent,
            "failed", "path_traversal_attempt"
        )
        logger.error(
            "Path traversal attempt by user %s: %s",
            user.username, file_path
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file path",
        )

    if not os.path.exists(file_path):
        await file_service.log_download_activity(
            db, user.id, file_id, ip_address, user_agent,
            "failed", "file_not_on_disk"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on server",
        )

    await file_service.log_download_activity(
        db, user.id, file_id, ip_address, user_agent,
        "success"
    )

    logger.info(
        "File downloaded: user=%s, file=%s, ip=%s",
        user.username, file.original_filename, ip_address
    )

    return FileResponse(
        path=file_path,
        filename=file.original_filename,
        media_type=file.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file.original_filename}"',
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/{file_id}/download-history", response_model=list[DownloadHistoryResponse])
async def get_download_history(
    file_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    file = await file_service.get_file_by_id(db, file_id)
    if not file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found",
        )

    history = await file_service.get_user_download_history(db, user.id, limit=20)

    file_history = [h for h in history if h.file_id == file_id]

    return [
        DownloadHistoryResponse(
            file_id=h.file_id,
            filename=file.original_filename,
            status=h.status,
            downloaded_at=h.downloaded_at,
            ip_address=h.ip_address,
        )
        for h in file_history
    ]
