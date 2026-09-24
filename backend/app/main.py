import os
import logging
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .database import engine, Base, SessionLocal
from .models.models import User
from .models.email_models import EmailRecord, EmailHeader, EmailAttachment, EmailUrlAnalysis, EmailDetection, EmailAlert, EmailQuarantine, EmailScanEvent, EmailMonitoringConfig, EmailProcessedUID
from .security.auth import get_password_hash, ADMIN_ROLE, USER_ROLE
from .security.middleware import (
    ALLOWED_ORIGINS,
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    UploadSecurityMiddleware,
)
from .routes import auth, files, scans, dashboard, quarantine, logs, reports, antivirus, realtime, features, hash_lookup, threat_intel, network_share, usb_scanner, email_security, settings, sandbox, firewall

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

UPLOADS_DIR = os.getenv("UPLOADS_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads"))
QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "quarantine"))


def _ensure_schema_columns():
    """Add missing columns to existing tables (SQLite ALTER TABLE compatibility)."""
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    try:
        columns = [col["name"] for col in inspector.get_columns("users")]
        if "role" not in columns:
            with engine.connect() as conn:
                conn.execute(text('ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT "USER" NOT NULL'))
                conn.commit()
            logger.info("Added missing 'role' column to users table.")
    except Exception as e:
        logger.warning(f"Schema migration error (non-fatal): {e}")


def _ensure_email_schema_columns():
    """Add Email Security columns added after the initial deploy (SQLite ALTER TABLE).

    Additive only - never drops or rewrites existing tables/columns.
    """
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    email_record_adds = {
        "spf": "VARCHAR(20)",
        "dkim": "VARCHAR(20)",
        "dmarc": "VARCHAR(20)",
        "scan_source": "VARCHAR(50) DEFAULT 'imap'",
    }
    config_adds = {
        "last_success_check": "DATETIME",
        "last_error": "TEXT",
        "connection_status": "VARCHAR(20) DEFAULT 'unknown'",
        "last_heartbeat": "DATETIME",
        "emails_checked": "INTEGER DEFAULT 0",
        "threats_detected": "INTEGER DEFAULT 0",
        "quarantined_attachments": "INTEGER DEFAULT 0",
    }
    try:
        email_columns = [col["name"] for col in inspector.get_columns("email_records")]
        for col, ddl in email_record_adds.items():
            if col not in email_columns:
                with engine.connect() as conn:
                    conn.execute(text(f'ALTER TABLE email_records ADD COLUMN "{col}" {ddl}'))
                    conn.commit()
                logger.info("Added email_records.%s column.", col)
    except Exception as e:
        logger.warning(f"Email schema migration error on email_records (non-fatal): {e}")

    try:
        config_columns = [col["name"] for col in inspector.get_columns("email_monitoring_config")]
        for col, ddl in config_adds.items():
            if col not in config_columns:
                with engine.connect() as conn:
                    conn.execute(text(f'ALTER TABLE email_monitoring_config ADD COLUMN "{col}" {ddl}'))
                    conn.commit()
                logger.info("Added email_monitoring_config.%s column.", col)
    except Exception as e:
        logger.warning(f"Email schema migration error on email_monitoring_config (non-fatal): {e}")

    try:
        with engine.connect() as conn:
            tables = {t for (t,) in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "email_processed_uids" not in tables:
            Base.metadata.create_all(bind=engine, tables=[EmailProcessedUID.__table__])
            logger.info("Created email_processed_uids table.")
    except Exception as e:
        logger.warning(f"Email schema migration error on email_processed_uids (non-fatal): {e}")


def _migrate_existing_users():
    """Migrate existing users: set role based on is_admin flag."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for user in users:
            changed = False
            if user.is_admin and user.role != ADMIN_ROLE:
                user.role = ADMIN_ROLE
                changed = True
            elif not user.is_admin and user.role == ADMIN_ROLE:
                user.is_admin = True
                changed = True
            elif not user.role:
                user.role = USER_ROLE if not user.is_admin else ADMIN_ROLE
                changed = True
            if changed:
                db.commit()
    except Exception as e:
        logger.warning(f"User migration error (non-fatal): {e}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    jwt_secret = os.getenv("JWT_SECRET", "")
    if not jwt_secret or jwt_secret in ("dev-secret-key-change-in-production", "change-this-to-a-random-secret-key-in-production", ""):
        logger.critical(
            "CRITICAL: JWT_SECRET is not set or is using a default value! "
            "Generate a strong secret with: python -c \"import secrets; print(secrets.token_hex(32))\" "
            "and set it in your .env file. The application will continue but is INSECURE."
        )
    elif len(jwt_secret) < 32:
        logger.warning("WARNING: JWT_SECRET is shorter than 32 characters. Use a longer secret for better security.")

    secret_key = os.getenv("SECRET_KEY", "")
    if not secret_key or secret_key in ("change-this-to-a-random-secret-key-in-production", ""):
        logger.warning(
            "SECRET_KEY is not set or is using a default value. "
            "Generate a strong secret with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created.")

    _ensure_schema_columns()
    _ensure_email_schema_columns()
    _migrate_existing_users()

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    logger.info(f"Directories ensured: {UPLOADS_DIR}, {QUARANTINE_DIR}")

    from .routes.antivirus import _monitored_paths
    from .services import folder_monitor
    if _monitored_paths:
        for path in _monitored_paths:
            if os.path.isdir(path):
                folder_monitor.start_monitoring(path)
                logger.info(f"Auto-started monitoring: {path}")

    from .services.email_monitor_service import email_monitor
    from .models.email_models import EmailMonitoringConfig
    db = SessionLocal()
    try:
        active_configs = db.query(EmailMonitoringConfig).filter(EmailMonitoringConfig.is_active == True).all()
        for config in active_configs:
            email_monitor.update_config(config.id, {
                "is_active": True,
                "imap_host": config.imap_host,
                "imap_port": config.imap_port,
                "use_ssl": config.use_ssl,
                "username": config.username,
                "password": config.password_encrypted,
                "folders_to_monitor": config.folders_to_monitor,
                "last_uid": config.last_uid or 0,
            })
        if active_configs:
            email_monitor.start()
            logger.info(f"Email monitor started with {len(active_configs)} active config(s)")
    except Exception as e:
        logger.warning(f"Could not auto-start email monitor: {e}")
    finally:
        db.close()

    async def _broadcast_health():
        from .services.health_service import get_system_health
        from .services.ws_manager import manager
        while True:
            try:
                health = get_system_health()
                await manager.broadcast_health_update(health)
            except Exception as e:
                logger.error(f"Health broadcast error: {e}")
            await asyncio.sleep(3)

    health_broadcast_task = asyncio.create_task(_broadcast_health())
    logger.info("Health broadcast task started (every 3s)")

    yield

    health_broadcast_task.cancel()
    try:
        await health_broadcast_task
    except asyncio.CancelledError:
        pass

    from .services import folder_monitor
    from .services.email_monitor_service import email_monitor as em
    em.stop()
    folder_monitor.stop_monitoring()
    logger.info("Application shutting down.")


app = FastAPI(
    title="Malicious File Detection System",
    description="Backend API for detecting malicious files using multiple analysis techniques",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, requests_per_minute=120)
app.add_middleware(UploadSecurityMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

app.include_router(auth.router)
app.include_router(files.router)
app.include_router(scans.router)
app.include_router(dashboard.router)
app.include_router(quarantine.router)
app.include_router(logs.router)
app.include_router(reports.router)
app.include_router(antivirus.router)
app.include_router(realtime.router)
app.include_router(features.router)
app.include_router(hash_lookup.router)
app.include_router(threat_intel.router)
app.include_router(network_share.router)
app.include_router(usb_scanner.router)
app.include_router(email_security.router)
app.include_router(settings.router)
app.include_router(sandbox.router)
app.include_router(firewall.router)


@app.get("/")
def root():
    return {
        "name": "Malicious File Detection System",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}
