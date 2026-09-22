import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..models.models import AuditLog

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")


def create_alert(
    scan_result: dict,
    db: Session,
    user_id: Optional[int] = None,
) -> dict:
    """Create an alert based on scan results and optionally email admin."""
    classification = scan_result.get("classification", "unknown")
    risk_score = scan_result.get("risk_score", 0)
    filename = scan_result.get("original_filename", "Unknown")
    reasons = scan_result.get("detection_reasons", [])

    if classification not in ("malicious", "suspicious"):
        return {"alert_created": False, "reason": "File not suspicious enough"}

    severity = "HIGH" if classification == "malicious" else "MEDIUM"

    alert_details = {
        "alert_type": classification,
        "severity": severity,
        "risk_score": risk_score,
        "filename": filename,
        "detection_reasons": reasons,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log = AuditLog(
        user_id=user_id,
        action="security_alert",
        details=f"Alert: {severity} risk detected for {filename}. Score: {risk_score}. Reasons: {'; '.join(reasons)}",
        result="alert",
    )
    db.add(log)
    db.commit()

    if SMTP_HOST and SMTP_USER:
        _send_alert_email(alert_details)

    logger.warning(
        f"Security Alert [{severity}]: {filename} (Score: {risk_score})"
    )

    return {"alert_created": True, "alert": alert_details}


def get_alerts(db: Session, limit: int = 50) -> List[AuditLog]:
    """Retrieve security alerts from audit logs."""
    return db.query(AuditLog).filter(
        AuditLog.action == "security_alert"
    ).order_by(AuditLog.timestamp.desc()).limit(limit).all()


def _send_alert_email(alert_details: dict) -> bool:
    """Send alert email via SMTP if configured."""
    if not SMTP_HOST or not SMTP_USER:
        logger.info("SMTP not configured. Skipping email alert.")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = SMTP_USER
        msg["Subject"] = f"[{alert_details['severity']}] Malicious File Alert - {alert_details['filename']}"

        body = f"""
Security Alert - Malicious File Detected

Severity: {alert_details['severity']}
Filename: {alert_details['filename']}
Risk Score: {alert_details['risk_score']}/100
Classification: {alert_details['alert_type']}
Timestamp: {alert_details['timestamp']}

Detection Reasons:
{chr(10).join(f'  - {r}' for r in alert_details['detection_reasons'])}

This is an automated alert from the Malicious File Detection System.
"""
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        logger.info("Alert email sent successfully.")
        return True

    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
        return False


def send_notification(subject: str, body: str, to_email: Optional[str] = None) -> bool:
    """Send a general notification email."""
    if not SMTP_HOST or not SMTP_USER:
        return False

    try:
        msg = MIMEText(body)
        msg["From"] = SMTP_USER
        msg["To"] = to_email or SMTP_USER
        msg["Subject"] = subject

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        return True
    except Exception as e:
        logger.error(f"Notification email failed: {e}")
        return False
