from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class FileDownloadLog(Base):
    __tablename__ = "file_download_logs"
    __table_args__ = (
        Index("ix_file_downloads_user_id_created_at", "user_id", "created_at"),
        Index("ix_file_downloads_file_name", "file_name"),
        Index("ix_file_downloads_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    file_hash: Mapped[str | None] = mapped_column(String(255))
    mime_type: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(Text)
    download_status: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
