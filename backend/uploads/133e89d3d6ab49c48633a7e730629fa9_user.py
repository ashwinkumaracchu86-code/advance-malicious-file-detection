import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_user_username"),
        UniqueConstraint("email", name="uq_user_email"),
        UniqueConstraint("phone_number", name="uq_user_phone_number"),
        Index("ix_users_email_active", "email", "is_active"),
        Index("ix_users_phone_number", "phone_number"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    public_id: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    phone_number: Mapped[str | None] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    account_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending_verification"
    )
    is_verified: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)
    two_factor_enabled: Mapped[bool] = mapped_column(default=False)
    two_factor_method: Mapped[str | None] = mapped_column(String(20))
    failed_login_attempts: Mapped[int] = mapped_column(default=0)
    last_failed_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(45))
    metadata_json: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
