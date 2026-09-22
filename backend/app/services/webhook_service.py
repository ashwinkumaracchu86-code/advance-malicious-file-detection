import os
import json
import logging
import requests
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..models.models import SystemSetting

logger = logging.getLogger(__name__)

WEBHOOK_SLACK_URL = os.getenv("WEBHOOK_SLACK_URL", "")
WEBHOOK_DISCORD_URL = os.getenv("WEBHOOK_DISCORD_URL", "")
WEBHOOK_CUSTOM_URL = os.getenv("WEBHOOK_CUSTOM_URL", "")


def send_slack_alert(title: str, message: str, severity: str = "info", url: Optional[str] = None) -> bool:
    """Send alert to Slack webhook."""
    webhook_url = url or WEBHOOK_SLACK_URL
    if not webhook_url:
        logger.info("Slack webhook not configured")
        return False

    color_map = {
        "info": "#36a64f",
        "warning": "#ff9900",
        "danger": "#ff0000",
        "critical": "#cc0000",
    }

    payload = {
        "attachments": [
            {
                "color": color_map.get(severity, "#36a64f"),
                "title": f"[MFDS] {title}",
                "text": message,
                "footer": "Malicious File Detection System",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Slack alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False


def send_discord_alert(title: str, message: str, severity: str = "info", url: Optional[str] = None) -> bool:
    """Send alert to Discord webhook."""
    webhook_url = url or WEBHOOK_DISCORD_URL
    if not webhook_url:
        logger.info("Discord webhook not configured")
        return False

    color_map = {
        "info": 0x36A64F,
        "warning": 0xFF9900,
        "danger": 0xFF0000,
        "critical": 0xCC0000,
    }

    payload = {
        "embeds": [
            {
                "title": f"[MFDS] {title}",
                "description": message,
                "color": color_map.get(severity, 0x36A64F),
                "footer": {"text": "Malicious File Detection System"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Discord alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Discord alert failed: {e}")
        return False


def send_custom_webhook(title: str, message: str, severity: str = "info", data: Optional[Dict] = None, url: Optional[str] = None) -> bool:
    """Send alert to custom webhook URL."""
    webhook_url = url or WEBHOOK_CUSTOM_URL
    if not webhook_url:
        logger.info("Custom webhook not configured")
        return False

    payload = {
        "title": title,
        "message": message,
        "severity": severity,
        "source": "malicious-file-detection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Custom webhook alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Custom webhook alert failed: {e}")
        return False


def send_threat_alert(filename: str, risk_score: float, classification: str, reasons: list) -> Dict[str, Any]:
    """Send threat alert to all configured webhooks."""
    severity = "danger" if classification == "malicious" else "warning"
    title = f"Threat Detected: {filename}"
    message = f"File: {filename}\nRisk Score: {risk_score}/100\nClassification: {classification.upper()}\nReasons:\n" + "\n".join(f"- {r}" for r in reasons)

    results = {
        "slack": send_slack_alert(title, message, severity),
        "discord": send_discord_alert(title, message, severity),
        "custom": send_custom_webhook(title, message, severity, {
            "filename": filename,
            "risk_score": risk_score,
            "classification": classification,
            "reasons": reasons,
        }),
    }

    return results


def get_webhook_status() -> Dict[str, Any]:
    """Get status of all webhook configurations."""
    return {
        "slack": {"configured": bool(WEBHOOK_SLACK_URL), "url": WEBHOOK_SLACK_URL[:30] + "..." if len(WEBHOOK_SLACK_URL) > 30 else WEBHOOK_SLACK_URL},
        "discord": {"configured": bool(WEBHOOK_DISCORD_URL), "url": WEBHOOK_DISCORD_URL[:30] + "..." if len(WEBHOOK_DISCORD_URL) > 30 else WEBHOOK_DISCORD_URL},
        "custom": {"configured": bool(WEBHOOK_CUSTOM_URL), "url": WEBHOOK_CUSTOM_URL[:30] + "..." if len(WEBHOOK_CUSTOM_URL) > 30 else WEBHOOK_CUSTOM_URL},
    }


def _get_setting(db: Session, key: str) -> str:
    """Read a value from the system_settings table."""
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row else ""


def _set_setting(db: Session, key: str, value: str):
    """Write a value to the system_settings table."""
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(SystemSetting(key=key, value=value))
    db.commit()


def get_webhook_urls(db: Session) -> Dict[str, str]:
    """Get webhook URLs from database (falling back to env vars)."""
    slack = _get_setting(db, "webhook_slack_url") or WEBHOOK_SLACK_URL
    discord = _get_setting(db, "webhook_discord_url") or WEBHOOK_DISCORD_URL
    custom = _get_setting(db, "webhook_custom_url") or WEBHOOK_CUSTOM_URL
    return {"slack": slack, "discord": discord, "custom": custom}


def save_webhook_urls(db: Session, slack: Optional[str] = None, discord: Optional[str] = None, custom: Optional[str] = None):
    """Save webhook URLs to database."""
    if slack is not None:
        _set_setting(db, "webhook_slack_url", slack)
    if discord is not None:
        _set_setting(db, "webhook_discord_url", discord)
    if custom is not None:
        _set_setting(db, "webhook_custom_url", custom)


def get_webhook_status_db(db: Session) -> Dict[str, Any]:
    """Get webhook status using database-stored URLs."""
    urls = get_webhook_urls(db)
    return {
        "slack": {"configured": bool(urls["slack"]), "url": urls["slack"]},
        "discord": {"configured": bool(urls["discord"]), "url": urls["discord"]},
        "custom": {"configured": bool(urls["custom"]), "url": urls["custom"]},
    }
