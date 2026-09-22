import os
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog, SystemSetting
from ..security.auth import get_current_user
from ..scanner.file_analyzer import analyze_file
from ..scanner.hash_calculator import calculate_hashes
from ..scanner.mime_detector import detect_mime_type
from ..services.virustotal import query_hash
from ..services.alert_service import create_alert
from ..utils.helpers import sanitize_filename

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-share", tags=["Network Share Scanner"])

NETWORK_SHARES_KEY = "network_shares"


class NetworkShareConfig(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    path: str = Field(..., min_length=1, max_length=500)
    share_type: str = Field(default="local", pattern="^(smb|nfs|local)$")
    username: Optional[str] = None
    password: Optional[str] = None


class ScanNetworkPathRequest(BaseModel):
    path: str
    recursive: bool = True
    file_extensions: Optional[List[str]] = None


def get_saved_shares(db: Session) -> List[dict]:
    setting = db.query(SystemSetting).filter(SystemSetting.key == NETWORK_SHARES_KEY).first()
    if setting and setting.value:
        try:
            return json.loads(setting.value)
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def save_shares(shares: List[dict], db: Session):
    setting = db.query(SystemSetting).filter(SystemSetting.key == NETWORK_SHARES_KEY).first()
    if not setting:
        setting = SystemSetting(key=NETWORK_SHARES_KEY, value=json.dumps(shares))
        db.add(setting)
    else:
        setting.value = json.dumps(shares)
    db.commit()


def get_parent_path(path: str) -> Optional[str]:
    """Get parent path safely on both Windows and Linux."""
    parent = os.path.dirname(path)
    if parent == path:
        return None
    return parent


@router.get("/browse")
def browse_path(
    path: str = Query("/", max_length=500),
    current_user: User = Depends(get_current_user),
):
    """Browse directory contents for network share configuration."""
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    if not os.path.isdir(path):
        raise HTTPException(status_code=400, detail="Not a directory")

    try:
        entries = []
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            try:
                is_dir = os.path.isdir(full_path)
                is_readable = os.access(full_path, os.R_OK)
            except (PermissionError, OSError):
                is_dir = False
                is_readable = False

            entries.append({
                "name": item,
                "path": full_path,
                "is_dir": is_dir,
                "is_readable": is_readable,
            })

        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

        parent = get_parent_path(path)

        return {
            "current_path": path,
            "parent_path": parent,
            "entries": entries[:100],
            "total_entries": len(entries),
        }
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    except Exception as e:
        logger.error(f"Error browsing path {path}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/shares")
def list_shares(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List configured network shares."""
    shares = get_saved_shares(db)
    return {"shares": shares, "total": len(shares)}


@router.post("/shares")
def add_share(
    config: NetworkShareConfig,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a new network share configuration (admin only)."""
    shares = get_saved_shares(db)

    for existing in shares:
        if existing["path"] == config.path:
            raise HTTPException(status_code=400, detail="Share path already configured")

    share = {
        "id": uuid.uuid4().hex[:8],
        "name": config.name,
        "path": config.path,
        "share_type": config.share_type,
        "username": config.username,
        "status": "configured",
        "added_date": str(datetime.now(timezone.utc)),
    }
    shares.append(share)
    save_shares(shares, db)

    log = AuditLog(
        user_id=current_user.id,
        action="network_share_add",
        details=f"Added network share: {config.name} ({config.path})",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"share": share, "message": "Share added successfully"}


@router.delete("/shares/{share_id}")
def remove_share(
    share_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a network share configuration (admin only)."""
    shares = get_saved_shares(db)
    original_count = len(shares)
    shares = [s for s in shares if s.get("id") != share_id]

    if len(shares) == original_count:
        raise HTTPException(status_code=404, detail="Share not found")

    save_shares(shares, db)

    log = AuditLog(
        user_id=current_user.id,
        action="network_share_remove",
        details=f"Removed network share: {share_id}",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"message": "Share removed successfully"}


@router.post("/scan")
def scan_network_path(
    request: ScanNetworkPathRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan files at a network path or local directory."""
    scan_path = request.path

    if not os.path.exists(scan_path):
        raise HTTPException(status_code=404, detail=f"Path not found: {scan_path}")

    if not os.path.isdir(scan_path):
        raise HTTPException(status_code=400, detail="Path is not a directory")

    default_extensions = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh",
        ".doc", ".docx", ".pdf", ".zip", ".rar", ".scr", ".com", ".pif",
        ".msi", ".hta", ".cpl", ".wsf", ".reg"
    }
    extensions = set(request.file_extensions) if request.file_extensions else default_extensions

    files_to_scan = []
    try:
        for root, dirs, files in os.walk(scan_path):
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in extensions:
                    files_to_scan.append(os.path.join(root, filename))
            if not request.recursive:
                break
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied accessing path")

    if not files_to_scan:
        return {
            "message": "No matching files found",
            "files_found": 0,
            "files_scanned": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "results": [],
        }

    files_to_scan = files_to_scan[:50]

    uploads_dir = os.getenv(
        "UPLOADS_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "uploads")
    )
    os.makedirs(uploads_dir, exist_ok=True)

    results = []
    for file_path in files_to_scan:
        try:
            filename = os.path.basename(file_path)
            safe_name = sanitize_filename(filename)
            unique_name = f"{uuid.uuid4().hex}_{safe_name}"
            dest_path = os.path.join(uploads_dir, unique_name)

            import shutil
            shutil.copy2(file_path, dest_path)

            file_size = os.path.getsize(dest_path)
            hashes = calculate_hashes(dest_path)
            mime_type = detect_mime_type(dest_path)
            ext = os.path.splitext(safe_name)[1].lower()

            file_record = FileModel(
                original_filename=safe_name,
                stored_filename=unique_name,
                file_path=dest_path,
                file_size=file_size,
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                mime_type=mime_type,
                extension=ext,
                uploaded_by=current_user.id,
            )
            db.add(file_record)
            db.commit()
            db.refresh(file_record)

            vt_results = query_hash(hashes["sha256"])
            analysis = analyze_file(dest_path, vt_results)

            scan = Scan(
                file_id=file_record.id,
                user_id=current_user.id,
                risk_score=analysis.get("risk_score", 0),
                classification=analysis.get("classification", "unknown"),
                entropy=analysis.get("entropy", 0),
                suspicious_strings=json.dumps(analysis.get("suspicious_strings", []), default=str),
                detection_reasons=json.dumps(analysis.get("detection_reasons", []), default=str),
                vt_detections_count=vt_results.get("positives", 0) if vt_results else 0,
                vt_positives=vt_results.get("positives", 0) if vt_results else 0,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

            classification = analysis.get("classification", "unknown")
            if classification in ("malicious", "suspicious"):
                analysis["original_filename"] = safe_name
                create_alert(analysis, db, current_user.id)

            results.append({
                "original_path": file_path,
                "filename": safe_name,
                "file_id": file_record.id,
                "scan_id": scan.id,
                "risk_score": scan.risk_score,
                "classification": scan.classification,
            })

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            results.append({
                "original_path": file_path,
                "filename": os.path.basename(file_path),
                "error": str(e),
            })

    log = AuditLog(
        user_id=current_user.id,
        action="network_share_scan",
        details=f"Scanned {len(results)} files from {scan_path}",
        result="success",
    )
    db.add(log)
    db.commit()

    malicious_count = sum(1 for r in results if r.get("classification") == "malicious")
    suspicious_count = sum(1 for r in results if r.get("classification") == "suspicious")

    return {
        "files_found": len(files_to_scan),
        "files_scanned": len(results),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "results": results,
    }
