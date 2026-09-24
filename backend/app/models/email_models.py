from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey, Text, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from ..database import Base


class EmailRecord(Base):
    __tablename__ = "email_records"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(255), unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    sender = Column(String(255), nullable=False, index=True)
    sender_domain = Column(String(255), index=True)
    recipient = Column(String(255))
    subject = Column(Text)
    date_received = Column(DateTime, index=True)
    body_text = Column(Text)
    body_html = Column(Text)
    raw_headers = Column(Text)
    mailchimp_id = Column(String(255))
    x_mailer = Column(String(255))
    return_path = Column(String(255))
    reply_to = Column(String(255))
    risk_score = Column(Float, default=0.0)
    classification = Column(String(20), default="safe", index=True)
    is_quarantined = Column(Boolean, default=False, index=True)
    is_read = Column(Boolean, default=False)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    scan_duration_ms = Column(Integer, default=0)
    total_attachments = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    url_count = Column(Integer, default=0)
    spam_score = Column(Float, default=0.0)
    phishing_score = Column(Float, default=0.0)
    spf = Column(String(20))
    dkim = Column(String(20))
    dmarc = Column(String(20))
    scan_source = Column(String(50), default="imap")

    user = relationship("User", backref="email_records")
    headers = relationship("EmailHeader", back_populates="email", cascade="all, delete-orphan")
    attachments = relationship("EmailAttachment", back_populates="email", cascade="all, delete-orphan")
    url_analyses = relationship("EmailUrlAnalysis", back_populates="email", cascade="all, delete-orphan")
    detections = relationship("EmailDetection", back_populates="email", cascade="all, delete-orphan")
    alerts = relationship("EmailAlert", back_populates="email", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_email_risk", "risk_score", "classification"),
        Index("idx_email_sender_domain", "sender_domain"),
    )


class EmailHeader(Base):
    __tablename__ = "email_headers"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    header_name = Column(String(100), nullable=False)
    header_value = Column(Text)

    email = relationship("EmailRecord", back_populates="headers")


class EmailAttachment(Base):
    __tablename__ = "email_attachments"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100))
    file_size = Column(Integer, default=0)
    md5 = Column(String(32), index=True)
    sha1 = Column(String(40), index=True)
    sha256 = Column(String(64), index=True)
    extension = Column(String(20))
    detected_mime = Column(String(100))
    file_signature = Column(String(100))
    risk_score = Column(Float, default=0.0)
    classification = Column(String(20), default="safe")
    is_dangerous_extension = Column(Boolean, default=False)
    is_double_extension = Column(Boolean, default=False)
    is_mime_mismatch = Column(Boolean, default=False)
    entropy = Column(Float, default=0.0)
    detection_reasons = Column(Text, default="[]")
    clamav_result = Column(String(50))
    clamav_virus_name = Column(String(255))
    vt_detections = Column(Integer, default=0)
    vt_total = Column(Integer, default=0)
    quarantine_path = Column(String(500))
    is_quarantined = Column(Boolean, default=False)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    contains_macros = Column(Boolean, default=False)
    is_password_protected = Column(Boolean, default=False)

    email = relationship("EmailRecord", back_populates="attachments")

    __table_args__ = (
        Index("idx_attachment_sha256", "sha256"),
        Index("idx_attachment_classification", "classification"),
    )


class EmailUrlAnalysis(Base):
    __tablename__ = "email_url_analyses"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    is_https = Column(Boolean, default=False)
    is_ip_url = Column(Boolean, default=False)
    is_shortened = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    is_phishing = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    reputation = Column(String(50))
    detection_reasons = Column(Text, default="[]")
    found_in = Column(String(50))

    email = relationship("EmailRecord", back_populates="url_analyses")


class EmailDetection(Base):
    __tablename__ = "email_detections"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    detection_type = Column(String(50), nullable=False)
    rule_name = Column(String(255))
    description = Column(Text)
    severity = Column(String(20), default="medium")
    category = Column(String(50))
    points = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    email = relationship("EmailRecord", back_populates="detections")


class EmailAlert(Base):
    __tablename__ = "email_alerts"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    email = relationship("EmailRecord", back_populates="alerts")
    user = relationship("User", backref="email_alerts")


class EmailQuarantine(Base):
    __tablename__ = "email_quarantine"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    quarantine_path = Column(String(500))
    status = Column(String(20), default="quarantined", index=True)
    risk_score = Column(Float, default=0.0)
    classification = Column(String(20))
    reason = Column(Text)
    reviewed_by = Column(Integer, ForeignKey("users.id"))
    reviewed_at = Column(DateTime)
    action_taken = Column(String(50))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    email = relationship("EmailRecord", backref="quarantine_records")
    user = relationship("User", foreign_keys=[user_id], backref="email_quarantine_created")
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class EmailScanEvent(Base):
    __tablename__ = "email_scan_events"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("email_records.id"))
    event_type = Column(String(50), nullable=False, index=True)
    event_data = Column(Text)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source = Column(String(50), default="system")


class EmailMonitoringConfig(Base):
    __tablename__ = "email_monitoring_config"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(50), nullable=False)
    imap_host = Column(String(255))
    imap_port = Column(Integer, default=993)
    use_ssl = Column(Boolean, default=True)
    username = Column(String(255))
    password_encrypted = Column(Text)
    oauth_token = Column(Text)
    polling_interval_seconds = Column(Integer, default=60)
    is_active = Column(Boolean, default=False, index=True)
    last_check = Column(DateTime)
    last_uid = Column(Integer, default=0)
    folders_to_monitor = Column(Text, default='["INBOX"]')
    max_attachment_size_mb = Column(Integer, default=25)
    auto_quarantine_threshold = Column(Float, default=70.0)
    last_success_check = Column(DateTime)
    last_error = Column(Text)
    connection_status = Column(String(20), default="unknown")
    last_heartbeat = Column(DateTime)
    emails_checked = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    quarantined_attachments = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", backref="email_monitoring_configs")


class EmailProcessedUID(Base):
    """Persistent record of processed IMAP messages (UID) to prevent duplicate processing across restarts."""

    __tablename__ = "email_processed_uids"

    id = Column(Integer, primary_key=True, index=True)
    config_id = Column(Integer, ForeignKey("email_monitoring_config.id"), nullable=False)
    folder = Column(String(100), nullable=False)
    uid = Column(Integer, nullable=False)
    message_id = Column(String(255))
    processed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("config_id", "folder", "uid", name="uq_config_folder_uid"),
        Index("idx_processed_uid", "config_id", "folder", "uid"),
    )
