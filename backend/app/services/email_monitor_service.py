import imaplib
import email
from email.header import decode_header
import logging
import json
import hashlib
import re
import os
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..database import SessionLocal
from ..models.email_models import EmailRecord, EmailHeader, EmailAttachment, EmailUrlAnalysis, EmailDetection, EmailAlert, EmailScanEvent

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

DEANGERING_DOMAINS = [
    "login.com", "secure.com", "verify.com", "account.com",
    "update.com", "confirm.com", "support.com",
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

    spf_result = headers.get("Authentication-Results", "")
    if "spf=fail" in spf_result.lower() or "spf=softfail" in spf_result.lower():
        reasons.append("SPF authentication failed")
        score += 20

    if "dkim=fail" in spf_result.lower():
        reasons.append("DKIM authentication failed")
        score += 15

    if "dmarc=fail" in spf_result.lower():
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
        "Authentication-Results", "Received", "DKIM-Signature",
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
                        "filename": filename,
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
        "message_id": message_id,
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


class EmailMonitor:
    def __init__(self):
        self._running = False
        self._thread = None
        self._configs = {}
        self._lock = threading.Lock()
        self._seen_uids = set()
        self._callbacks = []
        self._ws_connections = set()
        self._ws_lock = threading.Lock()

    def _get_db(self):
        return SessionLocal()

    def register_callback(self, callback):
        self._callbacks.append(callback)

    def register_ws(self, ws):
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

        import asyncio
        message = json.dumps({"type": event_type, "data": data})
        with self._ws_lock:
            dead = set()
            for ws in self._ws_connections:
                try:
                    asyncio.get_event_loop().run_until_complete(ws.send_text(message))
                except Exception:
                    dead.add(ws)
            self._ws_connections -= dead

    def update_config(self, config_id: int, config: Dict):
        with self._lock:
            self._configs[config_id] = config

    def remove_config(self, config_id: int):
        with self._lock:
            self._configs.pop(config_id, None)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Email monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Email monitor stopped")

    def _monitor_loop(self):
        while self._running:
            with self._lock:
                configs = dict(self._configs)

            for config_id, config in configs.items():
                if not config.get("is_active"):
                    continue
                try:
                    self._check_mailbox(config_id, config)
                except Exception as e:
                    logger.error(f"Mailbox check error for config {config_id}: {e}")

            time.sleep(10)

    def _check_mailbox(self, config_id: int, config: Dict):
        host = config.get("imap_host")
        port = config.get("imap_port", 993)
        username = config.get("username")
        password = config.get("password")
        use_ssl = config.get("use_ssl", True)
        folders = json.loads(config.get("folders_to_monitor", '["INBOX"]'))
        last_uid = config.get("last_uid", 0)

        if not host or not username or not password:
            return

        try:
            if use_ssl:
                mail = imaplib.IMAP4_SSL(host, port)
            else:
                mail = imaplib.IMAP4(host, port)

            mail.login(username, password)

            new_uids = []
            for folder in folders:
                try:
                    status, _ = mail.select(folder, readonly=True)
                    if status != "OK":
                        continue

                    if last_uid > 0:
                        status, data = mail.uid("search", None, f"UID {last_uid + 1}:*")
                    else:
                        status, data = mail.uid("search", None, "ALL")

                    if status == "OK" and data[0]:
                        uid_list = data[0].split()
                        for uid_bytes in uid_list:
                            uid = int(uid_bytes)
                            if uid > last_uid:
                                new_uids.append((folder, uid))
                except Exception as e:
                    logger.error(f"Folder scan error: {e}")

            for folder, uid in new_uids:
                try:
                    status, msg_data = mail.uid("fetch", str(uid), "(RFC822)")
                    if status == "OK" and msg_data and msg_data[0]:
                        raw_email = msg_data[0][1]
                        self._process_new_email(config, folder, uid, raw_email)
                except Exception as e:
                    logger.error(f"Email fetch error: {e}")

            if new_uids:
                max_uid = max(uid for _, uid in new_uids)
                config["last_uid"] = max_uid
                config["last_check"] = datetime.now(timezone.utc).isoformat()

            mail.logout()

        except Exception as e:
            logger.error(f"IMAP connection error: {e}")

    def _process_new_email(self, config: Dict, folder: str, uid: int, raw_email: bytes):
        parsed = parse_eml_content(raw_email)

        sender_analysis = analyze_sender(
            parsed["sender"],
            parsed["display_name"],
            parsed["headers"],
        )

        subject_analysis = analyze_subject(parsed["subject"])

        body_analysis = analyze_body(parsed["body_text"], parsed["body_html"])

        all_reasons = []
        total_score = 0.0

        all_reasons.extend([{"type": "sender", "category": "sender", "reason": r, "description": r, "points": 10} for r in sender_analysis["reasons"]])
        total_score += sender_analysis["score"]

        all_reasons.extend([{"type": "subject", "category": "subject", "reason": r, "description": r, "points": 8} for r in subject_analysis["reasons"]])
        total_score += subject_analysis["score"]

        all_reasons.extend([{"type": "body", "category": "body", "reason": r, "description": r, "points": 5} for r in body_analysis["reasons"]])
        total_score += body_analysis["score"]

        total_score = min(100.0, total_score)

        if total_score >= 80:
            classification = "critical"
        elif total_score >= 60:
            classification = "malicious"
        elif total_score >= 30:
            classification = "suspicious"
        elif total_score >= 15:
            classification = "low_risk"
        else:
            classification = "safe"

        attachment_count = len(parsed["attachments"])
        url_count = len(body_analysis.get("urls_found", []))
        now = datetime.now(timezone.utc)

        try:
            db = self._get_db()
            try:
                email_record = EmailRecord(
                    message_id=parsed["message_id"],
                    user_id=1,
                    sender=parsed["sender"],
                    sender_domain=sender_analysis["domain"],
                    recipient=parsed["recipient"],
                    subject=parsed["subject"],
                    date_received=now,
                    body_text=parsed["body_text"],
                    body_html=parsed["body_html"],
                    raw_headers=json.dumps(parsed["headers"]),
                    return_path=parsed["headers"].get("Return-Path", ""),
                    reply_to=parsed["headers"].get("Reply-To", ""),
                    risk_score=total_score,
                    classification=classification,
                    total_attachments=attachment_count,
                    url_count=url_count,
                    threat_count=len(all_reasons),
                )
                db.add(email_record)
                db.flush()

                for h_name, h_val in list(parsed["headers"].items())[:50]:
                    db.add(EmailHeader(
                        email_id=email_record.id,
                        header_name=h_name,
                        header_value=str(h_val)[:2000],
                    ))

                for att in parsed["attachments"]:
                    att_data = att.get("data", b"")
                    db.add(EmailAttachment(
                        email_id=email_record.id,
                        filename=att["filename"],
                        content_type=att.get("content_type", ""),
                        file_size=att.get("size", 0),
                        md5=hashlib.md5(att_data).hexdigest(),
                        sha1=hashlib.sha1(att_data).hexdigest(),
                        sha256=hashlib.sha256(att_data).hexdigest(),
                        extension=os.path.splitext(att["filename"])[1].lower(),
                    ))

                for url in body_analysis.get("urls_found", []):
                    try:
                        parsed_url = urlparse(url)
                        db.add(EmailUrlAnalysis(
                            email_id=email_record.id,
                            url=url,
                            domain=parsed_url.hostname or "",
                            is_https=parsed_url.scheme == "https",
                            is_ip_url=is_ip_url(url),
                            is_shortened=is_url_shortened(url),
                        ))
                    except Exception:
                        pass

                for reason in all_reasons:
                    severity = "critical" if reason["points"] >= 20 else "high" if reason["points"] >= 15 else "medium" if reason["points"] >= 8 else "low"
                    db.add(EmailDetection(
                        email_id=email_record.id,
                        detection_type=reason["type"],
                        rule_name=reason["type"],
                        description=reason["description"],
                        severity=severity,
                        category=reason["category"],
                        points=reason["points"],
                    ))

                if classification in ("critical", "malicious") or total_score >= 60:
                    db.add(EmailAlert(
                        email_id=email_record.id,
                        user_id=1,
                        alert_type="threat_detected",
                        severity=classification,
                        title=f"Threat detected: {classification.upper()} email from {parsed['sender']}",
                        message=f"Subject: {parsed['subject']}\nRisk Score: {total_score}\nClassification: {classification}",
                    ))

                db.add(EmailScanEvent(
                    email_id=email_record.id,
                    event_type="email_received",
                    event_data=json.dumps({
                        "message_id": parsed["message_id"],
                        "sender": parsed["sender"],
                        "subject": parsed["subject"],
                        "classification": classification,
                        "risk_score": total_score,
                        "attachment_count": attachment_count,
                        "url_count": url_count,
                        "folder": folder,
                        "uid": uid,
                    }),
                    source="imap_monitor",
                ))

                db.commit()
                email_record_id = email_record.id
                logger.info(f"Persisted email record {email_record_id}: {parsed['subject'][:50]} - Score: {total_score} - Classification: {classification}")

            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist email: {e}")
                email_record_id = None
            finally:
                db.close()

            self._notify("email_received", {
                "id": email_record_id,
                "message_id": parsed["message_id"],
                "sender": parsed["sender"],
                "sender_domain": sender_analysis["domain"],
                "display_name": parsed["display_name"],
                "subject": parsed["subject"],
                "classification": classification,
                "risk_score": total_score,
                "attachment_count": attachment_count,
                "url_count": url_count,
                "folder": folder,
                "uid": uid,
                "reasons": all_reasons,
                "timestamp": now.isoformat(),
            })

            if classification in ("critical", "malicious") or total_score >= 60:
                self._notify("alert_generated", {
                    "id": email_record_id,
                    "classification": classification,
                    "risk_score": total_score,
                    "sender": parsed["sender"],
                    "subject": parsed["subject"],
                    "reasons": all_reasons,
                    "timestamp": now.isoformat(),
                })

            if attachment_count > 0:
                self._notify("attachments_detected", {
                    "id": email_record_id,
                    "count": attachment_count,
                    "sender": parsed["sender"],
                    "subject": parsed["subject"],
                    "timestamp": now.isoformat(),
                })

        except Exception as e:
            logger.error(f"Error processing email: {e}")


email_monitor = EmailMonitor()
