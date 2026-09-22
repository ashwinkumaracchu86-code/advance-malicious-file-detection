import os
import shutil
import json
import uuid
import logging
from datetime import datetime
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from ..database import get_db
from ..security.auth import get_current_user
from ..models.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/settings", tags=["Settings"])

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

API_KEYS_FILE = os.path.join(BASE_DIR, "api_keys.json")

SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
os.makedirs(SANDBOX_DIR, exist_ok=True)

SETTINGS_FILE = os.path.join(BASE_DIR, "system_settings.json")

DEFAULT_SETTINGS = {
    "general": {
        "system_name": "MFDS - Malicious File Detection System",
        "language": "en",
        "timezone": "UTC",
        "session_timeout": 30,
        "max_login_attempts": 5,
    },
    "notifications": {
        "email_enabled": False,
        "desktop_enabled": True,
        "sound_enabled": True,
        "threat_alerts": True,
        "scan_complete": True,
        "weekly_report": False,
    },
    "scan": {
        "auto_scan": True,
        "auto_quarantine": False,
        "scan_depth": "standard",
        "max_file_size_mb": 50,
        "hash_lookup_enabled": True,
        "entropy_enabled": True,
        "string_analysis_enabled": True,
        "pe_analysis_enabled": True,
        "clamav_enabled": True,
    },
    "security": {
        "password_min_length": 8,
        "require_uppercase": True,
        "require_numbers": True,
        "require_special": False,
        "session_timeout_minutes": 30,
        "lockout_after_attempts": 5,
        "lockout_duration_minutes": 15,
    },
    "advanced": {
        "debug_mode": False,
        "log_level": "INFO",
        "retention_days": 90,
        "max_upload_size_mb": 50,
        "rate_limit_per_minute": 120,
    },
    "appearance": {
        "theme": "dark",
    },
    "smtp": {
        "host": "",
        "port": "587",
        "username": "",
        "password": "",
        "use_tls": True,
    },
    "monitoring": {
        "default_folder": "",
    },
    "virustotal": {
        "api_key": "",
    },
}


def load_settings() -> Dict[str, Any]:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                saved = json.load(f)
            merged = DEFAULT_SETTINGS.copy()
            for section, values in saved.items():
                if section in merged and isinstance(values, dict):
                    merged[section] = {**merged[section], **values}
                else:
                    merged[section] = values
            return merged
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(data: Dict[str, Any]):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)


def load_api_keys():
    if os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, "r") as f:
            return json.load(f)
    return {"keys": []}


def save_api_keys(data):
    with open(API_KEYS_FILE, "w") as f:
        json.dump(data, f, indent=2)


@router.get("/backups")
def list_backups(current_user: User = Depends(get_current_user)):
    backups = []
    for f in os.listdir(BACKUP_DIR):
        if f.endswith(".db"):
            filepath = os.path.join(BACKUP_DIR, f)
            stat = os.stat(filepath)
            backups.append({
                "id": f,
                "filename": f,
                "size": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
    backups.sort(key=lambda x: x["created_at"], reverse=True)
    return {"backups": backups}


@router.post("/backup")
def create_backup(current_user: User = Depends(get_current_user)):
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "database", "malicious_files.db")
    if not os.path.exists(db_path):
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "malicious_files.db")

    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Database file not found")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)

    shutil.copy2(db_path, backup_path)

    stat = os.stat(backup_path)
    return {
        "id": backup_filename,
        "filename": backup_filename,
        "size": stat.st_size,
        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "message": "Backup created successfully",
    }


@router.post("/restore/{backup_id}")
def restore_backup(backup_id: str, current_user: User = Depends(get_current_user)):
    backup_path = os.path.join(BACKUP_DIR, backup_id)
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "database", "malicious_files.db")
    if not os.path.exists(db_path):
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "malicious_files.db")

    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Database file not found")

    shutil.copy2(backup_path, db_path)
    return {"message": "Database restored successfully"}


@router.delete("/backup/{backup_id}")
def delete_backup(backup_id: str, current_user: User = Depends(get_current_user)):
    backup_path = os.path.join(BACKUP_DIR, backup_id)
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    os.remove(backup_path)
    return {"message": "Backup deleted successfully"}


@router.get("/backup/{backup_id}/download")
def download_backup(backup_id: str, current_user: User = Depends(get_current_user)):
    backup_path = os.path.join(BACKUP_DIR, backup_id)
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    from fastapi.responses import FileResponse
    return FileResponse(
        backup_path,
        media_type="application/octet-stream",
        filename=backup_id,
    )


@router.get("/db-info")
def get_db_info(current_user: User = Depends(get_current_user)):
    db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "database", "malicious_files.db")
    if not os.path.exists(db_path):
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "malicious_files.db")

    if os.path.exists(db_path):
        stat = os.stat(db_path)
        return {
            "type": "SQLite",
            "size": stat.st_size,
            "lastModified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "path": db_path,
        }
    return {"type": "SQLite", "size": 0, "lastModified": None, "path": db_path}


@router.get("/api-keys")
def list_api_keys(current_user: User = Depends(get_current_user)):
    data = load_api_keys()
    return {"keys": data.get("keys", [])}


@router.post("/api-keys")
def create_api_key(
    name: str = Form(...),
    description: str = Form(""),
    current_user: User = Depends(get_current_user),
):
    data = load_api_keys()
    key = f"mfds_{uuid.uuid4().hex}"
    new_key = {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": description,
        "key": key,
        "active": True,
        "created_at": datetime.now().isoformat(),
        "user_id": current_user.id,
    }
    data["keys"].append(new_key)
    save_api_keys(data)
    return {"message": "API key created", "key": key, "id": new_key["id"]}


@router.delete("/api-keys/{key_id}")
def delete_api_key(key_id: str, current_user: User = Depends(get_current_user)):
    data = load_api_keys()
    data["keys"] = [k for k in data["keys"] if k["id"] != key_id]
    save_api_keys(data)
    return {"message": "API key deleted"}


@router.get("/api-keys/{key_id}")
def get_api_key(key_id: str, current_user: User = Depends(get_current_user)):
    data = load_api_keys()
    for key in data.get("keys", []):
        if key["id"] == key_id:
            return key
    raise HTTPException(status_code=404, detail="API key not found")


@router.get("")
def get_all_settings(current_user: User = Depends(get_current_user)):
    return load_settings()


@router.put("")
def update_all_settings(body: dict, current_user: User = Depends(get_current_user)):
    current = load_settings()
    for section, values in body.items():
        if isinstance(values, dict) and section in current and isinstance(current[section], dict):
            current[section] = {**current[section], **values}
        else:
            current[section] = values
    save_settings(current)

    log_level = current.get("advanced", {}).get("log_level", "INFO").upper()
    numeric_level = getattr(logging, log_level, logging.INFO)
    logging.getLogger().setLevel(numeric_level)
    for h in logging.getLogger().handlers:
        h.setLevel(numeric_level)
    logger.info(f"Log level changed to {log_level}")

    return {"message": "Settings saved successfully", "settings": current}


@router.get("/{key}")
def get_setting(key: str, current_user: User = Depends(get_current_user)):
    settings = load_settings()
    if key in settings:
        return {key: settings[key]}
    raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")


@router.put("/{key}")
def update_setting(key: str, body: dict, current_user: User = Depends(get_current_user)):
    settings = load_settings()
    settings[key] = body.get("value", body)
    save_settings(settings)
    return {"message": f"Setting '{key}' updated", key: settings[key]}


@router.get("/system/info")
def get_system_info(current_user: User = Depends(get_current_user)):
    from ..models.models import File as FileModel, Scan, AuditLog
    db_path = os.path.join(BASE_DIR, "database", "malicious_files.db")
    if not os.path.exists(db_path):
        db_path = os.path.join(BASE_DIR, "malicious_files.db")

    db_size = 0
    db_exists = os.path.exists(db_path)
    if db_exists:
        db_size = os.path.getsize(db_path)

    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.endswith(".db"):
                fp = os.path.join(BACKUP_DIR, f)
                st = os.stat(fp)
                backups.append({"filename": f, "size": st.st_size, "created_at": datetime.fromtimestamp(st.st_ctime).isoformat()})
    backups.sort(key=lambda x: x["created_at"], reverse=True)

    return {
        "database": {
            "type": "SQLite",
            "exists": db_exists,
            "size_bytes": db_size,
            "size_human": f"{db_size / (1024*1024):.2f} MB" if db_size > 0 else "0 B",
            "path": db_path,
        },
        "backups": {
            "count": len(backups),
            "latest": backups[0] if backups else None,
        },
    }
