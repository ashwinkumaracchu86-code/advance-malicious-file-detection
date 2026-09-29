from app.database import SessionLocal
from app.models.models import User
from app.models.email_models import EmailMonitoringConfig
from app.security.encryption import encrypt_value

db = SessionLocal()
try:
    for uid in [1, 2]:
        cfg = db.query(EmailMonitoringConfig).filter_by(user_id=uid).first()
        if not cfg:
            cfg = EmailMonitoringConfig(user_id=uid)
            db.add(cfg)
        cfg.provider = "gmail"
        cfg.imap_host = "imap.gmail.com"
        cfg.imap_port = 993
        cfg.use_ssl = True
        cfg.username = "acchugowda9482@gmail.com"
        cfg.password_encrypted = encrypt_value("wcmepqhmwiteqbol")
        cfg.folders_to_monitor = '["INBOX"]'
        cfg.is_active = True
        cfg.connection_status = "connected"
    db.commit()
    print("Successfully configured Gmail Google App Password for users 1 and 2.")
finally:
    db.close()
