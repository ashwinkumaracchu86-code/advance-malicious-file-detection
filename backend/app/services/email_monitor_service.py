import imaplib
import email
import socket
import asyncio
from email.header import decode_header
import logging
import json
import re
import os
import time
import threading
import tempfile
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError

from ..database import SessionLocal
from ..models.email_models import (
    EmailRecord, EmailHeader, EmailAttachment, EmailUrlAnalysis, EmailDetection,
    EmailAlert, EmailScanEvent, EmailQuarantine, EmailMonitoringConfig, EmailProcessedUID,
)
from ..models.models import File as FileRecord
from ..scanner.file_analyzer import analyze_file
from ..security.encryption import decrypt_value, encrypt_value
from ..services.email_risk_engine import calculate_email_risk_score
from ..services.quarantine_service import quarantine_file

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "account suspended", "password reset",
    "confirm your identity", "unauthorized activity", "security alert",
    "act now", "immediate action", "your account will be closed",
    "verify your email", "update your payment", "claim your prize",
    "you have won", "congratulations", "lottery", "inheritance",
    "wire transfer", "bank account", "social security", "credit card",
    "suspended", "locked", "compromised", "unusual sign-in",
    "security breach", "confirm your password", "click here immediately",
]

SUSPICIOUS_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
    "buff.ly", "ow.ly", "shorte.st", "adf.ly",
]

SPOOFED_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "instagram.com"],
    "bank": ["chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com"],
}

DANGEROUS_EXT = {
    '.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.vbs', '.vbe', '.js',
    '.jse', '.wsf', '.wsh', '.ps1', '.psm1', '.psd1', '.msi', '.pif', '.hta', '.cpl',
    '.docm', '.xlsm', '.pptm', '.dotm', '.msc', '.msp', '.lnk', '.reg',
}

IMAP_CONNECT_TIMEOUT = 30


def decode_mime_header(header_value: str) -> str:
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="ignore"))
        else:
            result.append(part)
    return " ".join(result)


def extract_email_address(from_header: str) -> Tuple[str, str]:
    match = re.search(r'<([^>]+)>', from_header)
    if match:
        email_addr = match.group(1)
        display_name = from_header[:match.start()].strip().strip('"')
    else:
        email_addr = from_header.strip()
        display_name = ""
    return email_addr, display_name


def get_domain(email_addr: str) -> str:
    parts = email_addr.split("@")
    return parts[1].lower() if len(parts) == 2 else ""


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def is_ip_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
    except Exception:
        return False


def is_url_shortened(url: str) -> bool:
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        return any(short in domain for short in SUSPICIOUS_DOMAINS)
    except Exception:
        return False


def check_display_name_spoofing(display_name: str, email_addr: str) -> List[str]:
    reasons = []
    display_lower = display_name.lower()
    email_domain = get_domain(email_addr)

    for brand, legit_domains in SPOOFED_BRANDS.items():
        if brand in display_lower:
            if email_domain not in legit_domains:
                reasons.append(f"Display name mentions '{brand}' but sender domain '{email_domain}' is not a legitimate {brand} domain")
    return reasons


def analyze_sender(email_addr: str, display_name: str, headers: Dict) -> Dict[str, Any]:
    domain = get_domain(email_addr)
    reasons = []
    score = 0

    spoofing = check_display_name_spoofing(display_name, email_addr)
    if spoofing:
        reasons.extend(spoofing)
        score += 25

    return_path = headers.get("Return-Path", "")
    if return_path:
        _, rp_email = extract_email_address(return_path)
        rp_domain = get_domain(rp_email)
        if rp_domain and rp_domain != domain:
            reasons.append(f"Return-Path domain '{rp_domain}' differs from sender domain '{domain}'")
            score += 15

    reply_to = headers.get("Reply-To", "")
    if reply_to:
        _, rt_email = extract_email_address(reply_to)
        rt_domain = get_domain(rt_email)
        if rt_domain and rt_domain != domain:
            reasons.append(f"Reply-To domain '{rt_domain}' differs from sender domain '{domain}'")
            score += 10

    auth = get_auth_results(headers)
    if auth.get("spf") == "FAIL":
        reasons.append("SPF authentication failed")
        score += 20
    if auth.get("dkim") == "FAIL":
        reasons.append("DKIM authentication failed")
        score += 15
    if auth.get("dmarc") == "FAIL":
        reasons.append("DMARC authentication failed")
        score += 20

    free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com"]
    if domain in free_domains and any(kw in display_name.lower() for kw in ["support", "security", "admin", "team", "service"]):
        reasons.append(f"Free email domain '{domain}' used with professional-sounding display name")
        score += 10

    return {
        "domain": domain,
        "display_name": display_name,
        "email_address": email_addr,
        "reasons": reasons,
        "score": min(score, 100),
    }


def analyze_subject(subject: str) -> Dict[str, Any]:
    reasons = []
    score = 0
    subject_lower = subject.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in subject_lower:
            reasons.append(f"Phishing keyword detected: '{keyword}'")
            score += 8

    if re.search(r'\b(free|winner|congratulations|prize|reward)\b', subject_lower):
        reasons.append("Contains prize/scam language")
        score += 12

    if subject.count("!") >= 3 or subject.isupper():
        reasons.append("Excessive urgency indicators (all caps or multiple exclamation marks)")
        score += 8

    if re.search(r'\b(re:|fw:|fwd:)\b', subject_lower) and any(kw in subject_lower for kw in ["urgent", "verify", "password"]):
        reasons.append("Forwarded/Replied phishing attempt")
        score += 10

    return {
        "subject": subject,
        "reasons": reasons,
        "score": min(score, 100),
    }


def analyze_body(body_text: str, body_html: str = "") -> Dict[str, Any]:
    reasons = []
    score = 0
    text_lower = (body_text or "").lower()
    html_lower = (body_html or "").lower()

    combined = text_lower + " " + html_lower

    for keyword in PHISHING_KEYWORDS:
        if keyword in combined:
            reasons.append(f"Phishing keyword in body: '{keyword}'")
            score += 5

    url_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    html_urls = url_pattern.findall(body_html or "")
    text_urls = extract_urls(body_text or "")
    all_urls = list(set(html_urls + text_urls))

    if len(all_urls) > 5:
        reasons.append(f"High URL count in email ({len(all_urls)} URLs found)")
        score += 10

    ip_urls = [u for u in all_urls if is_ip_url(u)]
    if ip_urls:
        reasons.append(f"IP-based URL(s) detected: {ip_urls[0]}")
        score += 20

    shortened = [u for u in all_urls if is_url_shortened(u)]
    if shortened:
        reasons.append(f"URL shortener(s) detected: {shortened[0]}")
        score += 15

    if re.search(r'<form[^>]*action=', body_html or "", re.IGNORECASE):
        reasons.append("HTML form found in email (potential credential harvesting)")
        score += 15

    if re.search(r'<iframe|<object|<embed|<applet', body_html or "", re.IGNORECASE):
        reasons.append("Embedded content detected in HTML email")
        score += 20

    if re.search(r'javascript:', body_html or "", re.IGNORECASE):
        reasons.append("JavaScript detected in email HTML")
        score += 25

    return {
        "reasons": reasons,
        "score": min(score, 100),
        "urls_found": all_urls,
    }


def get_auth_results(headers: Dict) -> Dict[str, str]:
    """Parse SPF / DKIM / DMARC results from Authentication-Results (and Received-SPF).

    Returns one of: PASS, FAIL, UNKNOWN, NOT AVAILABLE.
    """
    result = {"spf": "NOT AVAILABLE", "dkim": "NOT AVAILABLE", "dmarc": "NOT AVAILABLE"}

    auth_lines = []
    for key in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF"):
        if headers.get(key):
            auth_lines.append(str(headers[key]))

    combined = "\n".join(auth_lines)
    if not combined.strip():
        return result

    mappings = {
        "spf": ["spf", "spf="],
        "dkim": ["dkim", "dkim="],
        "dmarc": ["dmarc", "dmarc="],
    }
    for field, needles in mappings.items():
        match = None
        for needle in needles:
            pattern = re.compile(needle + r"=\s*([a-z]+)", re.IGNORECASE)
            matches = pattern.findall(combined)
            if matches:
                match = matches[-1]
                break
        if match is None:
            continue
        status = match.lower()
        if status in ("pass", "pass (good)", "ok"):
            result[field] = "PASS"
        elif status in ("fail", "hardfail", "softfail"):
            result[field] = "FAIL"
        else:
            result[field] = "UNKNOWN"

    return result


def parse_eml_content(raw_email: bytes) -> Dict[str, Any]:
    msg = email.message_from_bytes(raw_email)

    subject = decode_mime_header(msg.get("Subject", ""))
    from_header = decode_mime_header(msg.get("From", ""))
    sender_email, display_name = extract_email_address(from_header)
    to_header = msg.get("To", "")
    date_header = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    headers = {}
    important_headers = [
        "From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID",
        "Return-Path", "Reply-To", "X-Mailer", "X-Originating-IP",
        "Authentication-Results", "Received-SPF", "Received", "DKIM-Signature",
        "SPF", "X-Spam-Status", "X-Spam-Score",
    ]
    for h in important_headers:
        val = msg.get(h)
        if val:
            headers[h] = decode_mime_header(val) if isinstance(val, str) else val

    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition or part.get_filename():
                filename = decode_mime_header(part.get_filename() or "unnamed")
                payload = part.get_payload(decode=True)
                if payload:
                    attachments.append({
                        "filename": _safe_filename(filename),
                        "content_type": content_type,
                        "size": len(payload),
                        "data": payload,
                    })
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode("utf-8", errors="ignore")
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            ct = msg.get_content_type()
            decoded = payload.decode("utf-8", errors="ignore")
            if ct == "text/html":
                body_html = decoded
            else:
                body_text = decoded

    return {
        "message_id": (message_id or "").strip()[:255],
        "sender": sender_email,
        "display_name": display_name,
        "recipient": to_header,
        "subject": subject,
        "date": date_header,
        "body_text": body_text[:10000],
        "body_html": body_html[:50000],
        "headers": headers,
        "attachments": attachments,
    }


def _safe_filename(filename: str) -> str:
    filename = os.path.basename(filename or "unnamed").replace("\x00", "")
    if not filename:
        return "unnamed"
    return filename[:200]


def analyze_attachment(
    att: Dict[str, Any],
    max_attachment_size_mb: int = 25,
) -> Dict[str, Any]:
    """Analyze an email attachment using the EXISTING malware file-analysis pipeline.

    The file scanner is reused; files are only read from memory into a temp file
    for analysis. Files are NEVER executed.
    """
    filename = _safe_filename(att.get("filename", "unnamed"))
    data = att.get("data", b"") or b""
    content_type = att.get("content_type", "")
    ext = os.path.splitext(filename)[1].lower()
    reasons = []
    base = {
        "filename": filename,
        "content_type": content_type,
        "extension": ext,
        "size": len(data),
        "scanned": True,
        "skipped_reason": None,
        # Raw bytes retained (internal use only) so quarantine can move the file
        # without re-parsing the email. Never serialized to API responses.
        "_data": data,
    }

    max_bytes = max_attachment_size_mb * 1024 * 1024
    if max_bytes > 0 and len(data) > max_bytes:
        base.update({
            "scanned": False,
            "skipped_reason": "exceeds_max_size",
            "md5": hashlib.md5(data).hexdigest() if data else "",
            "sha256": hashlib.sha256(data).hexdigest() if data else "",
            "risk_score": 0.0,
            "classification": "safe",
            "detection_reasons": [f"Attachment skipped: exceeds {max_attachment_size_mb}MB limit"],
            "detected_mime": "",
        })
        return base

    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in data:
        base.update({
            "scanned": True,
            "md5": hashlib.md5(data).hexdigest() if data else "",
            "sha256": hashlib.sha256(data).hexdigest() if data else "",
            "risk_score": 100.0,
            "classification": "malicious",
            "detection_reasons": ["EICAR test signature detected (standard antivirus test file)"],
            "detected_mime": "text/plain",
            "is_dangerous_extension": ext in DANGEROUS_EXT,
            "is_double_extension": len(filename.split(".")) > 2,
            "eicar_detected": True,
        })
        return base

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=ext or ".bin", prefix="email_att_")
        with os.fdopen(fd, "wb") as f:
            f.write(data)

        result = analyze_file(tmp_path)

        sha256 = result.get("sha256", "") or hashlib.sha256(data).hexdigest()
        md5 = result.get("md5", "") or hashlib.md5(data).hexdigest()
        sha1 = result.get("sha1", "") or ""

        scanner_class = (result.get("classification") or "safe").lower()
        if scanner_class in ("malicious", "critical"):
            classification = "malicious"
        elif scanner_class == "suspicious":
            classification = "suspicious"
        elif ext in DANGEROUS_EXT or result.get("is_suspicious_mime"):
            classification = "suspicious"
        else:
            classification = "safe"

        reasons = list(result.get("detection_reasons") or [])
        if ext in DANGEROUS_EXT:
            reasons.append(f"Dangerous extension: {ext}")
        parts = filename.split(".")
        if len(parts) > 2:
            reasons.append(f"Double extension: {filename}")
        if result.get("is_suspicious_mime"):
            reasons.append(f"Suspicious MIME type: {result.get('mime_type', '')}")
        if result.get("extension_matches_mime") is False:
            reasons.append(f"Extension '{ext}' does not match MIME type '{result.get('mime_type', '')}'")
        if result.get("clamav_is_infected"):
            reasons.append(f"ClamAV detected: {result.get('clamav_virus_name', 'malware')}")
        reasons = list(dict.fromkeys([r for r in reasons if r]))

        base.update({
            "scanned": True,
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
            "detected_mime": result.get("mime_type", "") or content_type,
            "file_signature": result.get("file_signature"),
            "entropy": result.get("entropy", 0.0),
            "is_mime_mismatch": result.get("extension_matches_mime") is False,
            "is_dangerous_extension": ext in DANGEROUS_EXT,
            "is_double_extension": len(parts) > 2,
            "risk_score": round(float(result.get("risk_score", 0)), 2),
            "classification": classification,
            "detection_reasons": reasons,
            "reasons": reasons,
            "clamav_result": result.get("clamav_scan_result"),
            "clamav_virus_name": result.get("clamav_virus_name"),
            "is_quarantined": False,
            "quarantine_path": None,
        })
    except FileNotFoundError:
        base.update({
            "scanned": False,
            "skipped_reason": "analysis_io_error",
            "md5": hashlib.md5(data).hexdigest() if data else "",
            "sha256": hashlib.sha256(data).hexdigest() if data else "",
            "risk_score": 0.0,
            "classification": "safe",
            "detection_reasons": ["Attachment analysis unavailable (file I/O error)"],
            "detected_mime": "",
        })
    except Exception as exc:  # analysis failures must never break monitoring
        logger.error("Attachment analysis error for %s: %s", filename, exc)
        base.update({
            "scanned": False,
            "skipped_reason": "scanner_error",
            "md5": hashlib.md5(data).hexdigest() if data else "",
            "sha256": hashlib.sha256(data).hexdigest() if data else "",
            "risk_score": 0.0,
            "classification": "safe",
            "detection_reasons": ["Attachment scanner failed - treated as safe for display"],
            "detected_mime": "",
        })
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return base


def _safe_error_message(exception: Exception) -> str:
    """Convert IMAP exceptions into user-safe messages without leaking credentials."""
    text = str(exception)
    user_msg = "Mailbox check failed"
    try:
        lowered = text.lower()
        if "authentication" in lowered and ("invalid" in lowered or "failed" in lowered or "failure" in lowered):
            user_msg = "Authentication failed. Verify the email address and App Password, and confirm IMAP access is enabled for the account."
        elif "username or password" in lowered:
            user_msg = "Authentication failed. Verify the email address and App Password."
        elif "log in via your web browser" in lowered or "oauth" in lowered or "less secure" in lowered:
            user_msg = "Sign-in blocked by the provider. Use an App Password (requires two-step verification to be enabled)."
        elif "login" in lowered and "denied" in lowered:
            user_msg = "Login denied by the mail provider."
        elif "timed out" in lowered or "timeout" in lowered or "timedout" in lowered:
            user_msg = "Connection to the mail server timed out."
        elif "connection refused" in lowered or "connection reset" in lowered:
            user_msg = "Could not connect to the mail server."
        elif "imaplib" in lowered and "error" in lowered:
            user_msg = "Mail server rejected the command."
        else:
            user_msg = "Unable to reach the mail server. Check the host, port and network."
    except Exception:
        pass
    logger.debug("IMAP error detail (backend only): %s", text)
    return user_msg


class EmailMonitor:
    def __init__(self):
        self._running = False
        self._thread = None
        self._configs: Dict[int, Dict] = {}
        self._lock = threading.Lock()
        self._callbacks = []
        self._ws_connections = set()
        self._ws_lock = threading.Lock()
        self._loop = None

    def _get_db(self):
        return SessionLocal()

    def register_callback(self, callback):
        self._callbacks.append(callback)

    def register_ws(self, ws):
        # Capture the running asyncio loop so the background thread can safely
        # schedule coroutine sends without touching get_event_loop() from a
        # non-loop thread.
        try:
            loop = asyncio.get_running_loop()
            with self._lock:
                self._loop = loop
        except RuntimeError:
            pass
        with self._ws_lock:
            self._ws_connections.add(ws)

    def unregister_ws(self, ws):
        with self._ws_lock:
            self._ws_connections.discard(ws)

    def _notify(self, event_type: str, data: dict):
        for cb in self._callbacks:
            try:
                cb(event_type, data)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        message = json.dumps({"type": event_type, "data": data})
        with self._ws_lock:
            conns = list(self._ws_connections)
        if not conns:
            return

        loop = self._loop
        if loop is None or loop.is_closed():
            return

        def _on_done(fut, ws):
            try:
                exc = fut.exception() if not fut.cancelled() else Exception("cancelled")
            except Exception:
                exc = Exception("unknown")
            if exc is not None:
                with self._ws_lock:
                    self._ws_connections.discard(ws)

        for ws in conns:
            try:
                fut = asyncio.run_coroutine_threadsafe(ws.send_text(message), loop)
                fut.add_done_callback(lambda f, _ws=ws: _on_done(f, _ws))
            except Exception:
                with self._ws_lock:
                    self._ws_connections.discard(ws)

    def is_running(self) -> bool:
        return self._running

    def update_config(self, config_id: int, config: Dict):
        with self._lock:
            cfg = dict(config)
            cfg["_last_run"] = self._configs.get(config_id, {}).get("_last_run", 0)
            self._configs[config_id] = cfg

    def remove_config(self, config_id: int):
        with self._lock:
            self._configs.pop(config_id, None)

    def _load_configs_from_db(self):
        db = self._get_db()
        try:
            rows = db.query(EmailMonitoringConfig).filter(EmailMonitoringConfig.is_active == True).all()
            current: Dict[int, Dict] = {}
            for c in rows:
                current[c.id] = {
                    "id": c.id,
                    "user_id": c.user_id,
                    "is_active": bool(c.is_active),
                    "provider": c.provider,
                    "imap_host": c.imap_host,
                    "imap_port": c.imap_port,
                    "use_ssl": bool(c.use_ssl),
                    "username": c.username,
                    "password": c.password_encrypted or "",
                    "folders_to_monitor": c.folders_to_monitor or '["INBOX"]',
                    "polling_interval_seconds": int(c.polling_interval_seconds or 60),
                    "max_attachment_size_mb": int(c.max_attachment_size_mb or 25),
                    "auto_quarantine_threshold": float(c.auto_quarantine_threshold or 70.0),
                    "last_uid": c.last_uid or 0,
                    "emails_checked": c.emails_checked or 0,
                    "threats_detected": c.threats_detected or 0,
                    "quarantined_attachments": c.quarantined_attachments or 0,
                    "last_check": c.last_check,
                    "last_success_check": c.last_success_check,
                    "last_error": c.last_error,
                    "connection_status": c.connection_status or "unknown",
                }
            with self._lock:
                old = dict(self._configs)
                merged = {}
                for cid, cfg in current.items():
                    merged[cid] = {**cfg, "_last_run": old.get(cid, {}).get("_last_run", 0)}
                self._configs = merged
            logger.debug("Loaded %d active email monitoring config(s) from DB", len(current))
        except Exception as e:
            logger.error("Failed to load email monitoring configs from DB: %s", e)
        finally:
            db.close()

    def _update_db_state(self, config_id: int, **fields):
        db = self._get_db()
        try:
            row = db.query(EmailMonitoringConfig).filter(EmailMonitoringConfig.id == config_id).first()
            if not row:
                return
            for key, value in fields.items():
                if hasattr(row, key):
                    setattr(row, key, value)
            now = datetime.now(timezone.utc)
            row.updated_at = now
            db.commit()
        except Exception as e:
            logger.error("Failed to persist email monitor state for config %s: %s", config_id, e)
            db.rollback()
        finally:
            db.close()

    def update_counters(self, config_id: int, emails: int = 0, threats: int = 0, quarantined: int = 0):
        db = self._get_db()
        try:
            row = db.query(EmailMonitoringConfig).filter(EmailMonitoringConfig.id == config_id).first()
            if not row:
                return
            row.emails_checked = (row.emails_checked or 0) + emails
            row.threats_detected = (row.threats_detected or 0) + threats
            row.quarantined_attachments = (row.quarantined_attachments or 0) + quarantined
            db.commit()
        except Exception as e:
            logger.error("Failed to update email monitor counters: %s", e)
            db.rollback()
        finally:
            db.close()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, name="email-monitor", daemon=True)
        self._thread.start()
        logger.info("Email monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Email monitor stopped")

    def run_worker(self):
        """Long-running worker loop for standalone Render background-worker processes."""
        self.start()
        try:
            while self._running:
                time.sleep(5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def _monitor_loop(self):
        while self._running:
            try:
                self._load_configs_from_db()
            except Exception as e:
                logger.error("Email monitor config load error: %s", e)

            with self._lock:
                configs = dict(self._configs)

            now = time.monotonic()
            for config_id, config in configs.items():
                if not config.get("is_active"):
                    continue
                interval = max(10, int(config.get("polling_interval_seconds", 60)))
                last_run = config.get("_last_run", 0)
                if now - last_run < interval:
                    continue
                config["_last_run"] = now
                try:
                    self._check_mailbox(config_id, config)
                except Exception as e:
                    logger.error("Mailbox check error for config %s: %s", config_id, e)
                    self._set_connection_error(config_id, _safe_error_message(e))

            time.sleep(5)

    def _set_connection_error(self, config_id: int, safe_message: str):
        now = datetime.now(timezone.utc)
        self._update_db_state(
            config_id,
            connection_status="error",
            last_error=safe_message,
            last_check=now,
        )
        self._store_system_event(None, "connection_failed", {
            "config_id": config_id,
            "message": safe_message,
        }, source="imap_monitor")

    def _store_system_event(self, email_id, event_type, data, source="system"):
        db = self._get_db()
        try:
            db.add(EmailScanEvent(
                email_id=email_id, event_type=event_type,
                event_data=json.dumps(data, default=str), source=source,
            ))
            db.commit()
        except Exception as e:
            logger.error("Failed to store email scan event: %s", e)
            db.rollback()
        finally:
            db.close()

    def _get_processed_uids(self, config_id: int) -> Set[Tuple[str, int]]:
        db = self._get_db()
        try:
            rows = db.query(EmailProcessedUID).filter(
                EmailProcessedUID.config_id == config_id).all()
            return {(r.folder, r.uid) for r in rows}
        except Exception as e:
            logger.error("Failed to load processed UIDs: %s", e)
            return set()
        finally:
            db.close()

    def _claim_uid(self, config_id: int, folder: str, uid: int, message_id: str) -> bool:
        """Atomically claim a UID so another monitor (web/worker) does not re-process it."""
        db = self._get_db()
        try:
            db.add(EmailProcessedUID(
                config_id=config_id, folder=folder, uid=int(uid), message_id=message_id[:255],
            ))
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False
        except Exception as e:
            logger.error("Failed to claim UID %s/%s: %s", folder, uid, e)
            db.rollback()
            return False
        finally:
            db.close()

    def _check_mailbox(self, config_id: int, config: Dict):
        host = config.get("imap_host")
        port = int(config.get("imap_port", 993))
        username = config.get("username")
        password = decrypt_value(config.get("password", ""))
        use_ssl = bool(config.get("use_ssl", True))
        try:
            folders = json.loads(config.get("folders_to_monitor", '["INBOX"]'))
        except Exception:
            folders = ["INBOX"]
        if not folders:
            folders = ["INBOX"]

        if not host or not username or not password:
            self._set_connection_error(config_id, "Monitoring configuration is incomplete (host, username or password missing).")
            return

        mail = None
        try:
            try:
                if use_ssl:
                    mail = imaplib.IMAP4_SSL(host, port, timeout=IMAP_CONNECT_TIMEOUT)
                else:
                    mail = imaplib.IMAP4(host, port, timeout=IMAP_CONNECT_TIMEOUT)
            except TypeError:
                socket.setdefaulttimeout(IMAP_CONNECT_TIMEOUT)
                if use_ssl:
                    mail = imaplib.IMAP4_SSL(host, port)
                else:
                    mail = imaplib.IMAP4(host, port)

            try:
                mail.login(username, password)
            except imaplib.IMAP4.error as exc:
                self._set_connection_error(config_id, _safe_error_message(exc))
                return

            processed_uids = self._get_processed_uids(config_id)
            seen_uids: Set[Tuple[str, int]] = set()
            new_messages: List[Tuple[str, int]] = []

            for folder in folders:
                try:
                    status, _data = mail.select(f'"{folder}"', readonly=True)
                    if status != "OK":
                        logger.warning("Could not select mailbox folder: %s", folder)
                        continue

                    status, data = mail.uid("search", None, "ALL")
                    if status != "OK" or not data or not data[0]:
                        continue

                    uid_bytes_list = data[0].split()
                    for uid_bytes in uid_bytes_list:
                        try:
                            uid = int(uid_bytes)
                        except (ValueError, TypeError):
                            continue
                        seen_uids.add((folder, uid))
                        if (folder, uid) not in processed_uids:
                            new_messages.append((folder, uid))
                except Exception as exc:
                    logger.warning("Folder scan error for %s: %s", folder, exc)

            for folder, uid in new_messages:
                if not self._running:
                    break
                try:
                    status, msg_data = mail.uid("fetch", str(uid), "(RFC822)")
                    if status == "OK" and msg_data and msg_data[0]:
                        raw_email = msg_data[0][1]
                        self._process_new_email(config_id, config, folder, uid, raw_email)
                except Exception as exc:
                    logger.error("Email fetch error (uid=%s): %s", uid, exc)

            now = datetime.now(timezone.utc)
            max_uid = 0
            for folder, uid in seen_uids:
                if folder == "INBOX" and uid > max_uid:
                    max_uid = uid
            self._update_db_state(
                config_id,
                last_check=now,
                last_heartbeat=now,
                last_success_check=now,
                connection_status="connected",
                last_error=None,
                last_uid=max_uid,
            )

            self._store_system_event(None, "mailbox_checked", {
                "config_id": config_id,
                "folders": folders,
                "new_emails": len(new_messages),
            }, source="imap_monitor")

        except (imaplib.IMAP4.error, OSError, socket.timeout) as exc:
            self._set_connection_error(config_id, _safe_error_message(exc))
        finally:
            if mail is not None:
                try:
                    mail.logout()
                except Exception:
                    pass

    def _process_new_email(self, config_id: int, config: Dict, folder: str, uid: int, raw_email: bytes):
        parsed = parse_eml_content(raw_email)
        message_id = parsed["message_id"] or f"uid-{config_id}-{folder}-{uid}"

        if not self._claim_uid(config_id, folder, uid, message_id):
            logger.info("UID %s/%s already processed (skipped)", folder, uid)
            return

        user_id = int(config.get("user_id") or 1)
        now = datetime.now(timezone.utc)
        max_attachment_mb = int(config.get("max_attachment_size_mb", 25))
        auto_threshold = float(config.get("auto_quarantine_threshold", 70.0))

        sender_analysis = analyze_sender(parsed["sender"], parsed["display_name"], parsed["headers"])
        subject_analysis = analyze_subject(parsed["subject"])
        body_analysis = analyze_body(parsed["body_text"], parsed["body_html"])
        auth_results = get_auth_results(parsed["headers"])

        url_analyses = []
        for url in body_analysis.get("urls_found", []):
            try:
                parsed_url = urlparse(url)
                ctx = f"{parsed['subject']} {parsed['body_text']}".lower()
                ctx += parsed["body_html"].lower()
                suspicious = is_ip_url(url) or is_url_shortened(url)
                phishing_hint = any(kw in ctx for kw in ["verify", "password", "sign in", "login", "account", "confirm"])
                risk = 0
                url_reasons = []
                if is_ip_url(url):
                    risk += 30
                    url_reasons.append("IP-based URL")
                if is_url_shortened(url):
                    risk += 20
                    url_reasons.append("URL shortener")
                if suspicious and phishing_hint:
                    risk += 20
                    url_reasons.append("Suspicious URL in credential-related context")
                url_analyses.append({
                    "url": url,
                    "domain": parsed_url.hostname or "",
                    "is_https": parsed_url.scheme == "https",
                    "is_ip_url": is_ip_url(url),
                    "is_shortened": is_url_shortened(url),
                    "is_suspicious": bool(risk),
                    "is_phishing": bool(suspicious and phishing_hint),
                    "risk_score": min(risk, 100),
                    "reputation": "unknown",
                    "reasons": url_reasons,
                    "found_in": "body",
                })
            except Exception:
                pass

        attachment_analyses = [analyze_attachment(att, max_attachment_mb) for att in parsed["attachments"]]

        risk_result = calculate_email_risk_score(
            sender_analysis=sender_analysis,
            subject_analysis=subject_analysis,
            body_analysis=body_analysis,
            url_analyses=url_analyses,
            attachment_analyses=attachment_analyses,
        )

        classification = risk_result["classification"]
        risk_score = risk_result["risk_score"]

        db = self._get_db()
        persisted_id = None
        try:
            email_record = EmailRecord(
                message_id=message_id,
                user_id=user_id,
                sender=parsed["sender"],
                sender_domain=sender_analysis["domain"],
                recipient=parsed["recipient"],
                subject=parsed["subject"],
                date_received=now,
                body_text=parsed["body_text"],
                body_html=parsed["body_html"],
                raw_headers=json.dumps(parsed["headers"], default=str)[:10000],
                x_mailer=parsed["headers"].get("X-Mailer", ""),
                return_path=parsed["headers"].get("Return-Path", ""),
                reply_to=parsed["headers"].get("Reply-To", ""),
                risk_score=risk_score,
                classification=classification,
                total_attachments=len(attachment_analyses),
                threat_count=len(risk_result.get("reasons", [])),
                url_count=len(url_analyses),
                spf=auth_results.get("spf"),
                dkim=auth_results.get("dkim"),
                dmarc=auth_results.get("dmarc"),
                scan_source="imap",
                scan_date=now,
            )
            db.add(email_record)
            db.flush()

            for h_name, h_val in list(parsed["headers"].items())[:50]:
                db.add(EmailHeader(
                    email_id=email_record.id,
                    header_name=h_name,
                    header_value=str(h_val)[:2000],
                ))

            quarantined_count = 0
            for aa in attachment_analyses:
                att_row = EmailAttachment(
                    email_id=email_record.id,
                    filename=aa.get("filename", ""),
                    content_type=aa.get("content_type", ""),
                    file_size=aa.get("size", 0),
                    md5=aa.get("md5", ""),
                    sha1=aa.get("sha1", ""),
                    sha256=aa.get("sha256", ""),
                    extension=aa.get("extension", ""),
                    detected_mime=aa.get("detected_mime", ""),
                    file_signature=aa.get("file_signature"),
                    entropy=aa.get("entropy", 0.0),
                    risk_score=aa.get("risk_score", 0),
                    classification=aa.get("classification", "safe"),
                    is_dangerous_extension=aa.get("is_dangerous_extension", False),
                    is_double_extension=aa.get("is_double_extension", False),
                    is_mime_mismatch=aa.get("is_mime_mismatch", False),
                    detection_reasons=json.dumps(aa.get("detection_reasons", []), default=str),
                    clamav_result=aa.get("clamav_result"),
                    clamav_virus_name=aa.get("clamav_virus_name"),
                )
                db.add(att_row)
                db.flush()

                if aa.get("classification") == "malicious" or (aa.get("risk_score", 0) >= auto_threshold):
                    quarantine_path = self._quarantine_attachment(
                        config_id, db, email_record.id, user_id, att_row, aa,
                    )
                    if quarantine_path:
                        quarantined_count += 1
                        email_record.is_quarantined = True
                        self._notify("attachment_quarantined", {
                            "id": email_record.id,
                            "attachment_id": att_row.id,
                            "filename": aa.get("filename"),
                            "sender": parsed["sender"],
                            "subject": parsed["subject"],
                            "sha256": aa.get("sha256"),
                            "reason": "; ".join(aa.get("detection_reasons", [])[:3]),
                            "timestamp": now.isoformat(),
                        })
                        self._store_system_event(email_record.id, "attachment_quarantined", {
                            "email_id": email_record.id,
                            "attachment": aa.get("filename"),
                            "sha256": aa.get("sha256"),
                            "reason": "; ".join(aa.get("detection_reasons", [])[:5]),
                        }, source="imap_monitor")

            for ua in url_analyses:
                db.add(EmailUrlAnalysis(
                    email_id=email_record.id,
                    url=ua.get("url", ""),
                    domain=ua.get("domain", ""),
                    is_https=ua.get("is_https", False),
                    is_ip_url=ua.get("is_ip_url", False),
                    is_shortened=ua.get("is_shortened", False),
                    is_suspicious=ua.get("is_suspicious", False),
                    is_phishing=ua.get("is_phishing", False),
                    risk_score=ua.get("risk_score", 0),
                    reputation=ua.get("reputation", "unknown"),
                    detection_reasons=json.dumps(ua.get("reasons", []), default=str),
                    found_in=ua.get("found_in", "body"),
                ))

            for reason in risk_result.get("reasons", []):
                points = reason.get("points", 0)
                severity = "critical" if points >= 20 else "high" if points >= 10 else "medium"
                db.add(EmailDetection(
                    email_id=email_record.id,
                    detection_type=reason.get("category", "general"),
                    rule_name=reason.get("category", "general"),
                    description=reason.get("description", ""),
                    severity=severity,
                    category=reason.get("category", ""),
                    points=points,
                ))

            if classification in ("critical", "malicious") or risk_score >= 60:
                db.add(EmailAlert(
                    email_id=email_record.id,
                    user_id=user_id,
                    alert_type="threat_detected",
                    severity="critical" if classification == "critical" else "high",
                    title=f"{'CRITICAL' if classification == 'critical' else 'Malicious'} Email Detected",
                    message=f"Sender: {parsed['sender']}\nSubject: {parsed['subject']}\nScore: {risk_score}/100",
                ))
                email_record.is_quarantined = True

            if classification in ("critical", "malicious") or risk_score >= 60:
                db.add(EmailQuarantine(
                    email_id=email_record.id,
                    user_id=user_id,
                    risk_score=risk_score,
                    classification=classification,
                    reason=json.dumps([r.get("description", "") for r in risk_result.get("reasons", [])[:5]], default=str),
                ))

            event_type = "email_received"
            if classification in ("critical", "malicious"):
                event_type = "malicious_email"
            elif classification == "suspicious":
                event_type = "suspicious_email"
            else:
                event_type = "safe_email"

            db.add(EmailScanEvent(
                email_id=email_record.id,
                event_type=event_type,
                event_data=json.dumps({
                    "message_id": message_id,
                    "sender": parsed["sender"],
                    "subject": parsed["subject"],
                    "classification": classification,
                    "risk_score": risk_score,
                    "attachment_count": len(attachment_analyses),
                    "quarantined_attachments": quarantined_count,
                    "url_count": len(url_analyses),
                    "folder": folder,
                    "uid": uid,
                }, default=str),
                source="imap_monitor",
            ))

            db.commit()
            persisted_id = email_record.id
            logger.info(
                "Email %s persisted: subject=%r sender=%r score=%.1f classification=%s attachments=%d",
                persisted_id, parsed["subject"][:50], parsed["sender"], risk_score, classification, len(attachment_analyses),
            )
        except Exception as e:
            db.rollback()
            persisted_id = None
            logger.error("Failed to persist monitored email: %s", e)
        finally:
            db.close()

        if persisted_id is not None:
            self.update_counters(
                config_id,
                emails=1,
                threats=1 if classification in ("suspicious", "malicious", "critical") else 0,
                quarantined=quarantined_count if quarantined_count else 0,
            )
            self._notify(event_type, {
                "id": persisted_id,
                "message_id": message_id,
                "sender": parsed["sender"],
                "sender_domain": sender_analysis["domain"],
                "display_name": parsed["display_name"],
                "subject": parsed["subject"],
                "classification": classification,
                "risk_score": risk_score,
                "attachment_count": len(attachment_analyses),
                "quarantined_attachments": quarantined_count,
                "url_count": len(url_analyses),
                "folder": folder,
                "uid": uid,
                "spf": auth_results.get("spf"),
                "dkim": auth_results.get("dkim"),
                "dmarc": auth_results.get("dmarc"),
                "reasons": risk_result.get("reasons", [])[:10],
                "timestamp": now.isoformat(),
            })
        else:
            logger.error("Email processing failed for uid %s/%s", folder, uid)

    def _quarantine_attachment(
        self, config_id: int, db, email_id: int, user_id: int,
        att_row: EmailAttachment, aa: Dict[str, Any],
    ) -> Optional[str]:
        """Quarantine an email attachment using the EXISTING quarantine service.

        The shared quarantine service (`quarantine_file`) hard-requires an
        existing File row (`quarantine_items.file_id` is NOT NULL). Attachments do
        not belong to a previously uploaded File, so a File record is created for
        the attachment first; the existing quarantine mechanism then moves the
        file and links everything. Never executed.
        """
        tmp_path = None
        try:
            data = aa.get("_data") or b""
            if not data:
                return None

            fd, tmp_path = tempfile.mkstemp(
                suffix=aa.get("extension") or ".bin",
                prefix="email_q_",
            )
            with os.fdopen(fd, "wb") as f:
                f.write(data)

            stride_path = self._quarantine_via_file_record(
                tmp_path, aa, user_id,
            )
            tmp_path = None  # moved into quarantine by the existing mechanism when successful
            if stride_path is None:
                logger.error("Quarantine failed for attachment: %s", aa.get("filename"))
                return None

            att_row.is_quarantined = True
            att_row.quarantine_path = stride_path
            db.add(EmailQuarantine(
                email_id=email_id,
                user_id=user_id,
                quarantine_path=stride_path,
                risk_score=aa.get("risk_score", 0),
                classification="malicious" if aa.get("classification") == "malicious" else "quarantined",
                reason=json.dumps(aa.get("detection_reasons", [])[:5], default=str),
            ))
            db.flush()
            logger.info(
                "Attachment quarantined: %s sha256=%s -> %s",
                aa.get("filename"), aa.get("sha256", "")[:16], stride_path,
            )
            return stride_path
        except Exception as e:
            logger.error("Quarantine error for attachment %s: %s", aa.get("filename", ""), e)
            try:
                db.rollback()
            except Exception:
                pass
            return None
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _quarantine_via_file_record(
        self, tmp_path: str, aa: Dict[str, Any], user_id: int,
    ) -> Optional[str]:
        """Create a File row for the attachment, then reuse quarantine_file()."""
        db = self._get_db()
        try:
            filename = aa.get("filename", "attachment")
            file_rec = FileRecord(
                original_filename=filename,
                stored_filename=os.path.basename(tmp_path),
                file_path=tmp_path,
                file_size=aa.get("size", 0) or os.path.getsize(tmp_path),
                md5=aa.get("md5", "") or "",
                sha1=aa.get("sha1", "") or "",
                sha256=aa.get("sha256", "") or "",
                mime_type=aa.get("detected_mime") or aa.get("content_type", "") or "",
                extension=aa.get("extension") or "",
                uploaded_by=user_id,
            )
            db.add(file_rec)
            db.commit()
            db.refresh(file_rec)

            item = quarantine_file(
                tmp_path,
                filename,
                aa.get("sha256", "") or "",
                db,
                user_id=user_id,
            )
            if item is None:
                db.delete(file_rec)
                db.commit()
                return None
            return item.quarantine_path
        except Exception as e:
            logger.error("Quarantine (file record) error for %s: %s", aa.get("filename", ""), e)
            db.rollback()
            return None
        finally:
            db.close()


email_monitor = EmailMonitor()


def test_connection(
    imap_host: str,
    imap_port: int,
    use_ssl: bool,
    username: str,
    password: str,
    folders: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Test an IMAP connection without storing or logging the password."""
    if not imap_host or not username or not password:
        return {"status": "failed", "code": "incomplete_config",
                "message": "Host, username and password are required."}
    mail = None
    try:
        try:
            if use_ssl:
                mail = imaplib.IMAP4_SSL(imap_host, imap_port, timeout=IMAP_CONNECT_TIMEOUT)
            else:
                mail = imaplib.IMAP4(imap_host, imap_port, timeout=IMAP_CONNECT_TIMEOUT)
        except TypeError:
            socket.setdefaulttimeout(IMAP_CONNECT_TIMEOUT)
            if use_ssl:
                mail = imaplib.IMAP4_SSL(imap_host, imap_port)
            else:
                mail = imaplib.IMAP4(imap_host, imap_port)
    except (imaplib.IMAP4.error, OSError, socket.timeout) as exc:
        return {"status": "failed", "code": "connection_error", "message": _safe_error_message(exc), "server": imap_host}

    try:
        try:
            mail.login(username, password)
        except imaplib.IMAP4.error as exc:
            return {"status": "failed", "code": "auth_failed", "message": _safe_error_message(exc), "server": imap_host}

        checked = []
        for folder in (folders or ["INBOX"]):
            try:
                status, _data = mail.select(f'"{folder}"', readonly=True)
                checked.append({"name": folder, "ok": status == "OK"})
            except Exception as exc:
                checked.append({"name": folder, "ok": False,
                                "message": _safe_error_message(exc)})
        return {
            "status": "connected",
            "code": "ok",
            "message": "Connection successful",
            "server": imap_host,
            "folders": checked,
        }
    except Exception as exc:
        return {"status": "failed", "code": "error", "message": _safe_error_message(exc), "server": imap_host}
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                pass