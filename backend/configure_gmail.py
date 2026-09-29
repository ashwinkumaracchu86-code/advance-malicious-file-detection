import os
import sys
from app.database import SessionLocal
from app.models.models import User
from app.models.email_models import EmailMonitoringConfig
from app.security.encryption import encrypt_value

# Helper script for setting up email monitoring from environment variables or command-line args
# Usage: python configure_gmail.py <user_id> <email> <app_password>
user_id = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.getenv("EMAIL_USER_ID", "1"))
username = sys.argv[2] if len(sys.argv) > 2 else os.getenv("EMAIL_USERNAME", "")
app_password = sys.argv[3] if len(sys.argv) > 3 else os.getenv("EMAIL_APP_PASSWORD", "")

if not username or not app_password:
    print("Usage: python configure_gmail.py <user_id> <email> <app_password>")
    print("Or set EMAIL_USER_ID, EMAIL_USERNAME, EMAIL_APP_PASSWORD in environment.")
    sys.exit(0)

db = SessionLocal()
try:
    cfg = db.query(EmailMonitoringConfig).filter_by(user_id=user_id).first()
    if not cfg:
        cfg = EmailMonitoringConfig(user_id=user_id)
        db.add(cfg)
    cfg.provider = "gmail"
    cfg.imap_host = "imap.gmail.com"
    cfg.imap_port = 993
    cfg.use_ssl = True
    cfg.username = username.strip()
    cfg.password_encrypted = encrypt_value(app_password.strip().replace(" ", ""))
    cfg.folders_to_monitor = '["INBOX"]'
    cfg.is_active = True
    db.commit()
    print(f"Successfully configured email monitoring for user {user_id}: {username}")
finally:
    db.close()

