"""Initial database schema

Revision ID: 001_initial
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("public_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("phone_number", sa.String(20), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("account_status", sa.String(20), nullable=False, server_default="pending_verification"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("two_factor_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("two_factor_method", sa.String(20), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_failed_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("public_id", name="uq_user_public_id"),
        sa.UniqueConstraint("username", name="uq_user_username"),
        sa.UniqueConstraint("email", name="uq_user_email"),
        sa.UniqueConstraint("phone_number", name="uq_user_phone_number"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_email_active", "users", ["email", "is_verified"])
    op.create_index("ix_users_phone_number", "users", ["phone_number"])
    op.create_index("ix_users_public_id", "users", ["public_id"])

    # Create otp_codes table
    op.create_table(
        "otp_codes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(255), nullable=False),
        sa.Column("purpose", sa.String(50), nullable=False),
        sa.Column("channel", sa.String(20), nullable=False, server_default="sms"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_otp_user_id_purpose", "otp_codes", ["user_id", "purpose"])
    op.create_index("ix_otp_expires_at", "otp_codes", ["expires_at"])

    # Create login_attempts table
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("is_successful", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.String(100), nullable=True),
        sa.Column("geo_location", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_login_attempts_user_id_created_at", "login_attempts", ["user_id", "created_at"])
    op.create_index("ix_login_attempts_ip_address", "login_attempts", ["ip_address"])
    op.create_index("ix_login_attempts_email", "login_attempts", ["email"])

    # Create user_sessions table
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(255), nullable=False),
        sa.Column("refresh_token_hash", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("device_fingerprint", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(100), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_session_id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_token_hash", "user_sessions", ["token_hash"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])
    op.create_index("ix_user_sessions_is_active", "user_sessions", ["is_active"])

    # Create security_audit_logs table
    op.create_table(
        "security_audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("event_description", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_logs_user_id_created_at", "security_audit_logs", ["user_id", "created_at"])
    op.create_index("ix_audit_logs_event_type", "security_audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_created_at", "security_audit_logs", ["created_at"])
    op.create_index("ix_audit_logs_ip_address", "security_audit_logs", ["ip_address"])

    # Create file_download_logs table
    op.create_table(
        "file_download_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("file_hash", sa.String(255), nullable=True),
        sa.Column("mime_type", sa.String(100), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("download_status", sa.String(20), nullable=False, server_default="success"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_file_downloads_user_id_created_at", "file_download_logs", ["user_id", "created_at"])
    op.create_index("ix_file_downloads_file_name", "file_download_logs", ["file_name"])
    op.create_index("ix_file_downloads_created_at", "file_download_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("file_download_logs")
    op.drop_table("security_audit_logs")
    op.drop_table("user_sessions")
    op.drop_table("login_attempts")
    op.drop_table("otp_codes")
    op.drop_table("users")
