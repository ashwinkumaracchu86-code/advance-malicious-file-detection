from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SecurityAuditLog(Base):
    __tablename__ = "security_audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_id_created_at", "user_id", "created_at"),
        Index("ix_audit_logs_event_type", "event_type"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_ip_address", "ip_address"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"))
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    event_description: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(Text)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(100))
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
