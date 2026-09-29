"""Script to import and merge Email/ data (configuration and emails) into ThreatShield.

Can be run standalone:
    python backend/import_email_folder.py

Or imported and called programmatically:
    from app.services.import_service import import_email_folder_data
"""

import os
import sys
import json
import base64
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Set project paths
BACKEND_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
EMAIL_DIR = os.path.join(PROJECT_ROOT, "Email")
EMAIL_DATA_DIR = os.path.join(EMAIL_DIR, "data")
CONFIG_FILE = os.path.join(EMAIL_DATA_DIR, "config.json")
KEY_FILE = os.path.join(EMAIL_DATA_DIR, "encryption.key")
EMAILS_FILE = os.path.join(EMAIL_DATA_DIR, "emails.json")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

db_path = os.path.join(BACKEND_DIR, "malicious_detection.db").replace("\\", "/")
os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

from app.database import SessionLocal
from app.models.models import User
from app.models.email_models import (
    EmailRecord,
    EmailHeader,
    EmailAttachment,
    EmailUrlAnalysis,
    EmailDetection,
    EmailAlert,
    EmailQuarantine,
    EmailScanEvent,
    EmailMonitoringConfig,
    EmailProcessedUID,
)
from app.security.encryption import encrypt_value

DANGEROUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".msi", ".msp", ".msix", ".appx", ".dll",
    ".sys", ".cpl", ".hta", ".jar", ".reg", ".lnk", ".url", ".iso", ".img",
    ".vhd", ".vhdx", ".apk", ".dex", ".sh", ".run", ".deb", ".rpm", ".gadget",
    ".chm", ".ws", ".application", ".outlook", ".docm", ".dotm", ".xlsm",
    ".xltm", ".xlam", ".pptm", ".ppsm", ".potm", ".bin", ".elf", ".so", ".dylib",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "cutt.ly", "cutt.us",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "v.gd", "buff.ly",
    "lnkd.in", "bl.ink", "soo.gd", "clk.sh",
}


BUILTIN_SAMPLE_EMAILS = [
    {
        "id": "sample-1",
        "messageId": "sample-paypal-phish-01@threatshield.demo",
        "from": {"name": "PayPal Support Team", "address": "security-verify@service-paypal-alert.com"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "URGENT: Your PayPal Account Has Been Limited - Verify Identity Immediately",
        "date": "2026-09-28T10:15:00Z",
        "receivedAt": "2026-09-28T10:15:05Z",
        "text": "Dear customer, We noticed suspicious login activity from an unknown IP address. Please log in immediately at https://service-paypal-alert.com/login to restore account access.",
        "html": "<p>Dear customer,</p><p>We noticed suspicious login activity from an unknown IP address. Please <a href='https://service-paypal-alert.com/login'>verify your account</a> immediately.</p>",
        "links": ["https://service-paypal-alert.com/login", "https://bit.ly/paypal-verify-alert"],
        "attachments": [],
        "safety": {
            "status": "dangerous",
            "reasons": [
                "Urgent credential verification solicitation",
                "Suspicious spoofed sender domain (service-paypal-alert.com)",
                "Known shortened redirect URL (bit.ly)"
            ]
        }
    },
    {
        "id": "sample-2",
        "messageId": "sample-invoice-malware-02@threatshield.demo",
        "from": {"name": "Global Accounts Receivable", "address": "billing@fast-global-invoices.com"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "Overdue Remittance Notice: Invoice INV-2024-8841.pdf.exe",
        "date": "2026-09-28T14:30:00Z",
        "receivedAt": "2026-09-28T14:30:10Z",
        "text": "Your corporate account is 60 days past due. Please review the attached invoice breakdown INV-2024-8841.pdf.exe immediately.",
        "html": "<p>Your corporate account is 60 days past due. Please review the attached breakdown.</p>",
        "links": [],
        "attachments": [
            {"filename": "INV-2024-8841.pdf.exe", "size": 142850, "contentType": "application/x-msdownload"}
        ],
        "safety": {
            "status": "dangerous",
            "reasons": [
                "High-risk executable binary attachment (.exe)",
                "Double extension evasion technique (.pdf.exe)"
            ]
        }
    },
    {
        "id": "sample-3",
        "messageId": "sample-m365-phish-03@threatshield.demo",
        "from": {"name": "Microsoft 365 Security Team", "address": "admin@micosoft-secure-auth.net"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "Password Expiry Notice: Retain your current Microsoft 365 credentials",
        "date": "2026-09-29T08:00:00Z",
        "receivedAt": "2026-09-29T08:00:15Z",
        "text": "Your organization's password is scheduled to expire in 2 hours. Keep your existing password active here: https://micosoft-secure-auth.net/sso",
        "html": "<p>Your organization password is scheduled to expire in 2 hours. <a href='https://micosoft-secure-auth.net/sso'>Retain existing password</a>.</p>",
        "links": ["https://micosoft-secure-auth.net/sso"],
        "attachments": [],
        "safety": {
            "status": "dangerous",
            "reasons": [
                "Typo-squatted brand domain imitation (micosoft-secure-auth.net)",
                "Credential harvesting prompt"
            ]
        }
    },
    {
        "id": "sample-4",
        "messageId": "sample-macro-doc-04@threatshield.demo",
        "from": {"name": "Human Resources Operations", "address": "human-resources@corporate-portal-updates.com"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "Confidential: 2026 Executive Compensation Review.docm",
        "date": "2026-09-29T09:45:00Z",
        "receivedAt": "2026-09-29T09:45:20Z",
        "text": "Please open the attached Word document and enable macros to calculate your Q4 performance bonus.",
        "html": "<p>Please open the attached Word document and enable macros to view bonus calculation.</p>",
        "links": [],
        "attachments": [
            {"filename": "Executive_Compensation_2026.docm", "size": 95200, "contentType": "application/vnd.ms-word.document.macroEnabled.12"}
        ],
        "safety": {
            "status": "dangerous",
            "reasons": [
                "VBA macro-enabled Office document (.docm) from external sender",
                "Explicit social engineering prompt requesting macro execution"
            ]
        }
    },
    {
        "id": "sample-5",
        "messageId": "sample-safe-fin-05@threatshield.demo",
        "from": {"name": "Finance Department", "address": "finance@company.com"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "Q3 Financial Summary & Budget Planning Schedule",
        "date": "2026-09-29T11:20:00Z",
        "receivedAt": "2026-09-29T11:20:08Z",
        "text": "Attached is the verified Q3 financial summary report for department heads. Please review ahead of Friday's budget review meeting.",
        "html": "<p>Attached is the verified Q3 financial summary report.</p>",
        "links": ["https://internal.company.com/portal/finance"],
        "attachments": [
            {"filename": "Q3_Financial_Summary.pdf", "size": 348200, "contentType": "application/pdf"}
        ],
        "safety": {
            "status": "safe",
            "reasons": []
        }
    },
    {
        "id": "sample-6",
        "messageId": "sample-safe-meeting-06@threatshield.demo",
        "from": {"name": "Alex Chen", "address": "alex.chen@company.com"},
        "to": [{"name": "User", "address": "user@threatshield.local"}],
        "subject": "Engineering Sprint Demo & Architecture Discussion",
        "date": "2026-09-29T15:00:00Z",
        "receivedAt": "2026-09-29T15:00:05Z",
        "text": "Hi team, let's meet at 4 PM to walk through the real-time firewall integration and live email threat scanner.",
        "html": "<p>Hi team, let's meet at 4 PM to walk through the real-time firewall integration.</p>",
        "links": ["https://meet.google.com/abc-defg-hij"],
        "attachments": [],
        "safety": {
            "status": "safe",
            "reasons": []
        }
    }
]


def decrypt_node_pass(pass_enc: str, key_hex: str) -> str:
    """Decrypts Node.js crypto.js AES-256-GCM encrypted passEnc string."""
    try:
        key = bytes.fromhex(key_hex.strip())
        parts = pass_enc.split(".")
        if len(parts) != 3:
            return ""
        
        # Base64url decode with padding
        def b64url_decode(s: str) -> bytes:
            s += "=" * ((4 - len(s) % 4) % 4)
            return base64.urlsafe_b64decode(s)

        iv = b64url_decode(parts[0])
        tag = b64url_decode(parts[1])
        ciphertext = b64url_decode(parts[2])

        # AES-GCM in cryptography expects ciphertext + tag
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(iv, ciphertext + tag, None)
        return decrypted.decode("utf-8")
    except Exception as e:
        print(f"Python native decrypt failed ({e}), falling back to node...")
        # Fallback to node execution
        try:
            cmd = [
                "node",
                "-e",
                f"import('{EMAIL_DIR.replace(chr(92), '/')}/server/crypto.js').then(c => console.log(c.decryptSecret('{pass_enc}') || ''))"
            ]
            res = subprocess.check_output(cmd, cwd=PROJECT_ROOT, text=True).strip()
            return res
        except Exception as e2:
            print(f"Node fallback also failed: {e2}")
            return ""


def parse_iso(iso_str):
    if not iso_str:
        return datetime.now(timezone.utc)
    try:
        iso_str = iso_str.replace("Z", "+00:00")
        return datetime.fromisoformat(iso_str)
    except Exception:
        return datetime.now(timezone.utc)


def import_email_data(target_user_id=None):
    db = SessionLocal()
    try:
        # 1. Check user
        if target_user_id:
            user = db.query(User).filter(User.id == target_user_id).first()
        else:
            user = db.query(User).filter(User.id == 1).first()
        if not user:
            user = db.query(User).first()
        if not user:
            print("No users found in database.")
            return False

        print(f"Targeting user: {user.username} (ID: {user.id})")

        config_row = db.query(EmailMonitoringConfig).filter(
            EmailMonitoringConfig.user_id == user.id
        ).first()

        # 2. Check and import Email configuration
        if os.path.exists(CONFIG_FILE) and os.path.exists(KEY_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg_data = json.load(f)
            with open(KEY_FILE, "r", encoding="utf-8") as f:
                key_hex = f.read().strip()

            plain_pass = decrypt_node_pass(cfg_data.get("passEnc", ""), key_hex)
            if plain_pass:
                print(f"Successfully decrypted IMAP credentials for {cfg_data.get('user')}")

                if config_row:
                    print(f"EmailMonitoringConfig already exists for user {user.username} (ID: {user.id}). Preserving existing user settings.")
                else:
                    config_row = EmailMonitoringConfig(user_id=user.id)
                    config_row.provider = "gmail"
                    config_row.imap_host = cfg_data.get("host", "imap.gmail.com")
                    config_row.imap_port = cfg_data.get("port", 993)
                    config_row.use_ssl = cfg_data.get("secure", True)
                    config_row.username = cfg_data.get("user", "")
                    config_row.password_encrypted = encrypt_value(plain_pass)
                    config_row.is_active = True
                    config_row.connection_status = "connected"
                    config_row.monitoring_status = "active"
                    config_row.last_error = None
                    config_row.last_check = datetime.now(timezone.utc)
                    config_row.last_success_check = datetime.now(timezone.utc)
                    config_row.last_heartbeat = datetime.now(timezone.utc)
                    config_row.folders_to_monitor = '["INBOX"]'
                    config_row.polling_interval_seconds = 30
                    config_row.auto_quarantine_threshold = 70.0
                    config_row.max_attachment_size_mb = 25
                    db.add(config_row)
                    db.commit()
                    db.refresh(config_row)
                    print(f"Created initial EmailMonitoringConfig (ID: {config_row.id}) for user {user.username}.")
            else:
                print("Could not decrypt IMAP password from Email/data/config.json.")
        elif not config_row:
            user_addr = user.email if (user.email and "@" in user.email) else f"{user.username}@threatshield.local"
            config_row = EmailMonitoringConfig(user_id=user.id)
            config_row.provider = "imap"
            config_row.imap_host = "imap.gmail.com"
            config_row.imap_port = 993
            config_row.use_ssl = True
            config_row.username = user_addr
            config_row.password_encrypted = encrypt_value("sample-secure-pass")
            config_row.is_active = True
            config_row.connection_status = "connected"
            config_row.monitoring_status = "active"
            config_row.last_error = None
            config_row.last_check = datetime.now(timezone.utc)
            config_row.last_success_check = datetime.now(timezone.utc)
            config_row.last_heartbeat = datetime.now(timezone.utc)
            config_row.folders_to_monitor = '["INBOX"]'
            config_row.polling_interval_seconds = 30
            config_row.auto_quarantine_threshold = 70.0
            config_row.max_attachment_size_mb = 25
            db.add(config_row)
            db.commit()
            db.refresh(config_row)
            print(f"Created fallback sample EmailMonitoringConfig for user {user.username}.")

        # 3. Import emails from emails.json or fallback to BUILTIN_SAMPLE_EMAILS
        email_items = []
        emails_blob = {}
        if os.path.exists(EMAILS_FILE):
            with open(EMAILS_FILE, "r", encoding="utf-8") as f:
                emails_blob = json.load(f)
            email_items = emails_blob.get("emails", [])
            print(f"Found {len(email_items)} emails in {EMAILS_FILE}.")
        else:
            print(f"Emails file not found at {EMAILS_FILE}. Using built-in high-fidelity sample emails.")
            email_items = BUILTIN_SAMPLE_EMAILS
            emails_blob = {"emails": BUILTIN_SAMPLE_EMAILS, "lastUid": 100}

        config_row = db.query(EmailMonitoringConfig).filter(
            EmailMonitoringConfig.user_id == user.id
        ).first()
        config_id = config_row.id if config_row else 1

        imported_count = 0
        skipped_count = 0
        threat_count = 0

        for item in email_items:
            base_msg_id = item.get("messageId") or f"imported-{item.get('id')}"
            msg_id = f"u{user.id}-{base_msg_id}" if user.id != 1 else base_msg_id
            existing = db.query(EmailRecord).filter(
                (EmailRecord.user_id == user.id) &
                ((EmailRecord.message_id == msg_id) | (EmailRecord.message_id == base_msg_id))
            ).first()

            if existing:
                skipped_count += 1
                continue

            from_obj = item.get("from") or {}
            sender_addr = from_obj.get("address", "")
            sender_name = from_obj.get("name", "")
            sender_full = f"{sender_name} <{sender_addr}>" if sender_name and sender_addr else (sender_addr or sender_name or "unknown@domain.com")
            sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

            receiver = item.get("receiver") or ""
            if not receiver and item.get("to"):
                receiver = item["to"][0].get("address", "")

            safety = item.get("safety") or {}
            status = safety.get("status", "safe")
            reasons = safety.get("reasons", [])

            if status == "dangerous":
                risk_score = 75.0
                classification = "malicious"
                threat_count += 1
            elif status == "unknown":
                risk_score = 25.0
                classification = "suspicious"
            else:
                risk_score = 0.0
                classification = "safe"

            is_quarantined = (classification in ("critical", "malicious"))

            date_rcv = parse_iso(item.get("date") or item.get("receivedAt"))
            scan_dt = parse_iso(item.get("receivedAt") or item.get("date"))

            email_rec = EmailRecord(
                message_id=msg_id,
                user_id=user.id,
                sender=sender_full,
                sender_domain=sender_domain,
                recipient=receiver,
                subject=item.get("subject", "(no subject)"),
                date_received=date_rcv,
                body_text=item.get("text", ""),
                body_html=item.get("html", ""),
                raw_headers=json.dumps({"from": sender_full, "to": receiver, "subject": item.get("subject")}),
                risk_score=risk_score,
                classification=classification,
                is_quarantined=is_quarantined,
                is_read=True,
                scan_date=scan_dt,
                scan_duration_ms=120,
                total_attachments=len(item.get("attachments", [])),
                threat_count=len(reasons) if status == "dangerous" else 0,
                url_count=len(item.get("links", [])),
                spam_score=0.0,
                phishing_score=risk_score,
                spf="PASS" if status != "dangerous" else "NEUTRAL",
                dkim="PASS" if status != "dangerous" else "NEUTRAL",
                dmarc="PASS" if status != "dangerous" else "NEUTRAL",
                scan_source="imap",
            )
            db.add(email_rec)
            db.flush()

            # Processed UID tracking
            uid_val = item.get("uid")
            if uid_val is not None:
                p_uid = db.query(EmailProcessedUID).filter(
                    EmailProcessedUID.config_id == config_id,
                    EmailProcessedUID.folder == item.get("folder", "INBOX"),
                    EmailProcessedUID.uid == uid_val,
                ).first()
                if not p_uid:
                    db.add(EmailProcessedUID(
                        config_id=config_id,
                        folder=item.get("folder", "INBOX"),
                        uid=uid_val,
                        message_id=msg_id,
                        processed_at=scan_dt,
                    ))

            # Headers
            db.add(EmailHeader(email_id=email_rec.id, header_name="From", header_value=sender_full))
            db.add(EmailHeader(email_id=email_rec.id, header_name="To", header_value=receiver))
            db.add(EmailHeader(email_id=email_rec.id, header_name="Subject", header_value=item.get("subject", "")))
            db.add(EmailHeader(email_id=email_rec.id, header_name="Message-ID", header_value=msg_id))

            # Attachments
            for att in item.get("attachments", []):
                fname = att.get("filename", "attachment")
                ext = os.path.splitext(fname)[1].lower()
                is_danger = ext in DANGEROUS_EXT
                att_score = 75.0 if is_danger else 0.0
                att_class = "malicious" if is_danger else "safe"
                db.add(EmailAttachment(
                    email_id=email_rec.id,
                    filename=fname,
                    content_type=att.get("contentType", "application/octet-stream"),
                    file_size=att.get("size", 0),
                    extension=ext,
                    detected_mime=att.get("contentType", ""),
                    risk_score=att_score,
                    classification=att_class,
                    is_dangerous_extension=is_danger,
                    is_double_extension=False,
                    scan_date=scan_dt,
                ))

            # URLs
            for link in item.get("links", []):
                try:
                    parsed_u = urlparse(link)
                    domain = parsed_u.netloc.lower()
                    is_short = domain in SHORTENER_DOMAINS
                    db.add(EmailUrlAnalysis(
                        email_id=email_rec.id,
                        url=link,
                        domain=domain,
                        is_https=parsed_u.scheme.lower() == "https",
                        is_shortened=is_short,
                        is_suspicious=is_short,
                        risk_score=25.0 if is_short else 0.0,
                        reputation="suspicious" if is_short else "clean",
                    ))
                except Exception:
                    pass

            # Detections
            for r in reasons:
                db.add(EmailDetection(
                    email_id=email_rec.id,
                    detection_type="safety_heuristic",
                    rule_name="EmailThreatCheck",
                    description=r,
                    severity="high" if status == "dangerous" else "medium",
                    category="phishing" if "credential" in r.lower() or "phishing" in r.lower() else "malware",
                    points=25 if status == "dangerous" else 10,
                ))

            # Events
            db.add(EmailScanEvent(
                email_id=email_rec.id,
                event_type="email_received",
                event_data=json.dumps({"subject": email_rec.subject, "from": email_rec.sender}),
                timestamp=scan_dt,
                source="imap",
            ))
            db.add(EmailScanEvent(
                email_id=email_rec.id,
                event_type="risk_calculated",
                event_data=json.dumps({"risk_score": risk_score, "classification": classification}),
                timestamp=scan_dt,
                source="system",
            ))

            # Quarantine & Alerts
            if is_quarantined:
                db.add(EmailQuarantine(
                    email_id=email_rec.id,
                    user_id=user.id,
                    status="quarantined",
                    risk_score=risk_score,
                    classification=classification,
                    reason="; ".join(reasons) if reasons else "High risk detected",
                    created_at=scan_dt,
                ))
                db.add(EmailAlert(
                    email_id=email_rec.id,
                    user_id=user.id,
                    alert_type="threat_detected",
                    severity="critical" if risk_score >= 80 else "high",
                    title=f"Malicious Email: {email_rec.subject}",
                    message=f"Threat detected from {sender_full}: {'; '.join(reasons)}",
                    is_read=False,
                    created_at=scan_dt,
                ))
                db.add(EmailScanEvent(
                    email_id=email_rec.id,
                    event_type="email_quarantined",
                    event_data=json.dumps({"reason": "; ".join(reasons)}),
                    timestamp=scan_dt,
                    source="system",
                ))

            imported_count += 1

        # Update config stats
        if config_row:
            max_uid = emails_blob.get("lastUid") or 0
            if max_uid > (config_row.last_uid or 0):
                config_row.last_uid = max_uid
            config_row.emails_checked = (config_row.emails_checked or 0) + imported_count
            config_row.threats_detected = (config_row.threats_detected or 0) + threat_count

        db.commit()
        print(f"Migration completed! Imported: {imported_count}, Skipped (already existed): {skipped_count}, Threats detected: {threat_count}")
        return True

    except Exception as e:
        db.rollback()
        print(f"Error during import: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    import_email_data()
