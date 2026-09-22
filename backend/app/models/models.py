from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from ..database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    role = Column(String(20), default="USER", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    files = relationship("File", back_populates="uploader")
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

    @property
    def is_admin_role(self):
        return self.role == "ADMIN"


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=False)
    md5 = Column(String(32), index=True)
    sha1 = Column(String(40), index=True)
    sha256 = Column(String(64), index=True)
    mime_type = Column(String(100))
    extension = Column(String(20))
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    upload_date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_quarantined = Column(Boolean, default=False)

    uploader = relationship("User", back_populates="files")
    scans = relationship("Scan", back_populates="file", cascade="all, delete-orphan")
    quarantine_items = relationship("QuarantineItem", back_populates="file")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    risk_score = Column(Float, default=0.0)
    classification = Column(String(20), default="unknown")
    entropy = Column(Float, default=0.0)
    suspicious_strings = Column(Text, default="[]")
    detection_reasons = Column(Text, default="[]")
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    vt_detections_count = Column(Integer, default=0)
    vt_positives = Column(Integer, default=0)

    file = relationship("File", back_populates="scans")
    user = relationship("User", back_populates="scans")

    __table_args__ = (
        Index("idx_scan_classification", "classification"),
        Index("idx_scan_risk_score", "risk_score"),
    )


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    rule_name = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default="medium")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class QuarantineItem(Base):
    __tablename__ = "quarantine_items"

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    quarantine_path = Column(String(500), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), index=True)
    quarantine_date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String(20), default="quarantined")
    reviewed_by = Column(Integer, ForeignKey("users.id"))

    file = relationship("File", back_populates="quarantine_items")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    generated_by = Column(Integer, ForeignKey("users.id"))
    report_path = Column(String(500))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    result = Column(String(20), default="success")

    user = relationship("User", back_populates="audit_logs")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
