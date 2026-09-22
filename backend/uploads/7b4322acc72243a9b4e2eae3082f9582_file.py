from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ProtectedFile(Base):
    __tablename__ = "protected_files"
    __table_args__ = (
        Index("ix_protected_files_is_active", "is_active"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    file_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_2fa: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class DownloadToken(Base):
    __tablename__ = "download_tokens"
    __table_args__ = (
        Index("ix_download_tokens_token", "token"),
        Index("ix_download_tokens_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("protected_files.file_id"), nullable=False)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class DownloadActivity(Base):
    __tablename__ = "download_activities"
    __table_args__ = (
        Index("ix_download_activities_user_id", "user_id"),
        Index("ix_download_activities_file_id", "file_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("protected_files.file_id"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(100))
    downloaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
