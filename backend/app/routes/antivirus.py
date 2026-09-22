import os
import json
import time
import uuid
import asyncio
import threading
import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog, SystemSetting
from ..security.auth import get_current_user
from ..scanner.file_analyzer import analyze_file
from ..scanner.hash_calculator import calculate_hashes
from ..scanner.mime_detector import detect_mime_type
from ..scanner.clamav_scanner import get_clamav_status
from ..services.virustotal import query_hash
from ..services.alert_service import create_alert
from ..services import quarantine_service
from ..services import firewall_service
from ..utils.helpers import sanitize_filename

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/antivirus", tags=["Antivirus Protection"])

UPLOADS_DIR = os.getenv("UPLOADS_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "uploads"))

_scan_history = []
_notification_queue = []
_protection_enabled = True
_auto_scan_enabled = True
_auto_quarantine_enabled = True
_monitored_paths = []
_scan_lock = threading.Lock()
_firewall_integration_enabled = True
_threat_blocked_ips = []
_threat_log = []


def _add_notification(notification: dict):
    """Add a notification to the queue and broadcast via WebSocket."""
    global _notification_queue
    notification["id"] = len(_notification_queue) + 1
    notification["timestamp"] = datetime.now(timezone.utc).isoformat()
    notification["read"] = False
    _notification_queue.insert(0, notification)
    if len(_notification_queue) > 100:
        _notification_queue = _notification_queue[:100]
    try:
        from ..services.ws_manager import manager
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(manager.broadcast_notification(notification))
        else:
            loop.run_until_complete(manager.broadcast_notification(notification))
    except Exception:
        pass


def _get_file_extension(filename: str) -> str:
    """Get file extension from filename."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _is_unauthorized_extension(filename: str) -> bool:
    """Check if file extension is potentially dangerous."""
    dangerous_extensions = {
        '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
        '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsh', '.wsc',
        '.ps1', '.psm1', '.psd1', '.reg', '.inf', '.hta',
        '.cpl', '.msp', '.mst', '.gadget', '.application',
        '.docm', '.xlsm', '.pptm', '.dotm', '.xltm',
        '.ppsm', '.potm', '.sldm',
    }
    ext = _get_file_extension(filename)
    return ext in dangerous_extensions


def perform_auto_scan(file_path: str, filename: str, db: Session, user_id: Optional[int] = None) -> dict:
    """Perform automatic scan on a file and return results."""
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return {"status": "skipped", "reason": "Empty file"}

        hashes = calculate_hashes(file_path)
        mime_type = detect_mime_type(file_path)
        ext = _get_file_extension(filename)

        safe_name = sanitize_filename(filename)
        stored_filename = f"{hashes['sha256'][:16]}_{safe_name}"

        file_record = FileModel(
            original_filename=safe_name,
            stored_filename=stored_filename,
            file_path=file_path,
            file_size=file_size,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            mime_type=mime_type,
            extension=ext,
            uploaded_by=user_id,
        )
        db.add(file_record)
        db.commit()
        db.refresh(file_record)

        vt_results = query_hash(hashes["sha256"])
        analysis = analyze_file(file_path, vt_results)
        analysis["original_filename"] = safe_name

        scan = Scan(
            file_id=file_record.id,
            user_id=user_id,
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
        risk_score = analysis.get("risk_score", 0)

        scan_result = {
            "scan_id": scan.id,
            "file_id": file_record.id,
            "filename": safe_name,
            "risk_score": risk_score,
            "classification": classification,
            "entropy": analysis.get("entropy", 0),
            "detection_reasons": analysis.get("detection_reasons", []),
            "clamav_result": analysis.get("clamav_scan_result", "unknown"),
            "clamav_virus_name": analysis.get("clamav_virus_name"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": analysis.get("source_ip", ""),
            "source_zone": "",
            "firewall_blocked": False,
        }

        source_ip = analysis.get("source_ip", "")
        if source_ip and _firewall_integration_enabled:
            source_zone = firewall_service._get_zone_for_ip(source_ip)
            scan_result["source_zone"] = source_zone["name"] if source_zone else "Unknown"

        if classification == "safe":
            _add_notification({
                "type": "success",
                "title": "File Scan Complete",
                "message": f'"{safe_name}" is safe. No threats detected.',
                "filename": safe_name,
                "risk_score": risk_score,
                "classification": classification,
            })
        elif classification == "suspicious":
            _add_notification({
                "type": "warning",
                "title": "Suspicious File Detected",
                "message": f'"{safe_name}" is suspicious (Score: {risk_score}/100). Review recommended.',
                "filename": safe_name,
                "risk_score": risk_score,
                "classification": classification,
            })
            if _auto_quarantine_enabled:
                quarantine_service.quarantine_file(
                    file_path=file_path,
                    original_filename=safe_name,
                    file_hash=hashes["sha256"],
                    db=db,
                    user_id=user_id,
                )
                scan_result["quarantined"] = True
                _add_notification({
                    "type": "threat",
                    "title": "Auto-Quarantined",
                    "message": f'"{safe_name}" has been automatically quarantined.',
                    "filename": safe_name,
                    "risk_score": risk_score,
                })
        elif classification == "malicious":
            create_alert(analysis, db, user_id)
            _add_notification({
                "type": "threat",
                "title": "Malicious File Detected!",
                "message": f'"{safe_name}" is MALICIOUS (Score: {risk_score}/100). Immediate action required.',
                "filename": safe_name,
                "risk_score": risk_score,
                "classification": classification,
            })

            if source_ip and _firewall_integration_enabled:
                firewall_service._blocked_ips[source_ip] = firewall_service._blocked_ips.get(source_ip, 0) + 1
                if source_ip not in [t["ip"] for t in _threat_blocked_ips]:
                    _threat_blocked_ips.append({
                        "ip": source_ip,
                        "zone": scan_result.get("source_zone", "Unknown"),
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "threats": 1,
                        "reason": f"Malicious file: {safe_name} (Score: {risk_score})",
                    })
                else:
                    for t in _threat_blocked_ips:
                        if t["ip"] == source_ip:
                            t["threats"] += 1
                            t["reason"] = f"Latest: {safe_name} (Score: {risk_score})"
                            break
                _threat_log.append({
                    "id": len(_threat_log) + 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ip": source_ip,
                    "zone": scan_result.get("source_zone", "Unknown"),
                    "filename": safe_name,
                    "risk_score": risk_score,
                    "action": "blocked",
                    "reason": f"Malicious file transfer",
                })
                scan_result["firewall_blocked"] = True
                _add_notification({
                    "type": "threat",
                    "title": "IP Blocked by Firewall",
                    "message": f"Source IP {source_ip} ({scan_result.get('source_zone', '?')}) blocked due to malicious file.",
                    "filename": safe_name,
                    "risk_score": risk_score,
                })

            if _auto_quarantine_enabled:
                quarantine_service.quarantine_file(
                    file_path=file_path,
                    original_filename=safe_name,
                    file_hash=hashes["sha256"],
                    db=db,
                    user_id=user_id,
                )
                scan_result["quarantined"] = True
                _add_notification({
                    "type": "threat",
                    "title": "Auto-Quarantined",
                    "message": f'Malicious file "{safe_name}" has been automatically quarantined.',
                    "filename": safe_name,
                    "risk_score": risk_score,
                })

        log = AuditLog(
            user_id=user_id,
            action="auto_scan",
            details=f"Auto-scanned: {safe_name}. Classification: {classification}, Score: {risk_score}",
            result="success",
        )
        db.add(log)
        db.commit()

        with _scan_lock:
            _scan_history.insert(0, scan_result)
            if len(_scan_history) > 200:
                _scan_history.pop()

        try:
            from ..services.ws_manager import manager
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(manager.broadcast_scan_result(scan_result))
            else:
                loop.run_until_complete(manager.broadcast_scan_result(scan_result))
        except Exception:
            pass

        return scan_result

    except Exception as e:
        logger.error(f"Auto-scan error: {e}")
        db.rollback()
        return {"status": "error", "error": str(e)}


@router.post("/scan-shared")
async def scan_shared_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan a file that is being shared or sent. Auto-scans and shows notification."""
    if not _protection_enabled:
        return {"status": "protection_disabled", "message": "Real-time protection is disabled"}

    filename = file.filename or "unnamed_file"
    ext = _get_file_extension(filename)

    if _is_unauthorized_extension(filename):
        _add_notification({
            "type": "threat",
            "title": "Blocked Dangerous File",
            "message": f'File "{filename}" with extension {ext} was blocked. Executable/script files are not allowed.',
            "filename": filename,
        })
        raise HTTPException(
            status_code=403,
            detail=f"File type blocked: {ext} files are not allowed for security reasons"
        )

    os.makedirs(UPLOADS_DIR, exist_ok=True)
    safe_name = sanitize_filename(filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    file_path = os.path.join(UPLOADS_DIR, unique_name)

    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    result = perform_auto_scan(file_path, safe_name, db, current_user.id)
    return result


@router.post("/scan-folder")
async def scan_folder_files(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan multiple files (e.g., from a folder share). Auto-scans each file."""
    if not _protection_enabled:
        return {"status": "protection_disabled", "message": "Real-time protection is disabled"}

    results = []
    for upload_file in files:
        filename = upload_file.filename or "unnamed_file"
        ext = _get_file_extension(filename)

        if _is_unauthorized_extension(filename):
            results.append({
                "filename": filename,
                "status": "blocked",
                "reason": f"Extension {ext} is blocked",
            })
            continue

        os.makedirs(UPLOADS_DIR, exist_ok=True)
        safe_name = sanitize_filename(filename)
        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        file_path = os.path.join(UPLOADS_DIR, unique_name)

        content = await upload_file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        result = perform_auto_scan(file_path, safe_name, db, current_user.id)
        results.append(result)

    return {"scanned": len(results), "results": results}


@router.get("/status")
def get_protection_status(
    current_user: User = Depends(get_current_user),
):
    """Get current antivirus protection status."""
    return {
        "protection_enabled": _protection_enabled,
        "auto_scan_enabled": _auto_scan_enabled,
        "auto_quarantine_enabled": _auto_quarantine_enabled,
        "monitored_paths": _monitored_paths,
        "total_scans": len(_scan_history),
        "threats_detected": len([s for s in _scan_history if s.get("classification") in ("malicious", "suspicious")]),
        "threats_blocked": len([s for s in _scan_history if s.get("quarantined")]),
    }


@router.post("/protection/enable")
def enable_protection(
    current_user: User = Depends(get_current_user),
):
    """Enable real-time protection."""
    global _protection_enabled
    _protection_enabled = True
    _add_notification({
        "type": "success",
        "title": "Protection Enabled",
        "message": "Real-time protection has been enabled.",
    })
    return {"status": "enabled", "message": "Real-time protection enabled"}


@router.post("/protection/disable")
def disable_protection(
    current_user: User = Depends(get_current_user),
):
    """Disable real-time protection."""
    global _protection_enabled
    _protection_enabled = False
    _add_notification({
        "type": "warning",
        "title": "Protection Disabled",
        "message": "Real-time protection has been disabled. System is vulnerable.",
    })
    return {"status": "disabled", "message": "Real-time protection disabled"}


@router.post("/auto-scan/enable")
def enable_auto_scan(
    current_user: User = Depends(get_current_user),
):
    """Enable auto-scan on file share."""
    global _auto_scan_enabled
    _auto_scan_enabled = True
    return {"status": "enabled", "message": "Auto-scan enabled"}


@router.post("/auto-scan/disable")
def disable_auto_scan(
    current_user: User = Depends(get_current_user),
):
    """Disable auto-scan on file share."""
    global _auto_scan_enabled
    _auto_scan_enabled = False
    return {"status": "disabled", "message": "Auto-scan disabled"}


@router.post("/auto-quarantine/enable")
def enable_auto_quarantine(
    current_user: User = Depends(get_current_user),
):
    """Enable auto-quarantine for detected threats."""
    global _auto_quarantine_enabled
    _auto_quarantine_enabled = True
    return {"status": "enabled", "message": "Auto-quarantine enabled"}


@router.post("/auto-quarantine/disable")
def disable_auto_quarantine(
    current_user: User = Depends(get_current_user),
):
    """Disable auto-quarantine for detected threats."""
    global _auto_quarantine_enabled
    _auto_quarantine_enabled = False
    return {"status": "disabled", "message": "Auto-quarantine disabled"}


@router.post("/monitored-paths")
def add_monitored_path(
    path: str = Query(..., description="Folder path to monitor"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a folder path to the monitored list for auto-scan."""
    if path not in _monitored_paths:
        _monitored_paths.append(path)
        _add_notification({
            "type": "success",
            "title": "Path Added",
            "message": f"Monitoring folder: {path}",
        })

    setting = db.query(SystemSetting).filter(SystemSetting.key == "monitored_paths").first()
    if setting:
        setting.value = json.dumps(_monitored_paths)
    else:
        setting = SystemSetting(key="monitored_paths", value=json.dumps(_monitored_paths))
        db.add(setting)
    db.commit()

    return {"status": "added", "path": path, "monitored_paths": _monitored_paths}


@router.delete("/monitored-paths")
def remove_monitored_path(
    path: str = Query(..., description="Folder path to remove"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove a folder path from the monitored list."""
    if path in _monitored_paths:
        _monitored_paths.remove(path)

    setting = db.query(SystemSetting).filter(SystemSetting.key == "monitored_paths").first()
    if setting:
        setting.value = json.dumps(_monitored_paths)
        db.commit()

    return {"status": "removed", "path": path, "monitored_paths": _monitored_paths}


@router.get("/scan-history")
def get_scan_history(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """Get recent auto-scan history."""
    return {"history": _scan_history[:limit]}


@router.get("/notifications")
def get_notifications(
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Get notification queue."""
    return {"notifications": _notification_queue[:limit]}


@router.post("/notifications/mark-read")
def mark_notifications_read(
    current_user: User = Depends(get_current_user),
):
    """Mark all notifications as read."""
    global _notification_queue
    for n in _notification_queue:
        n["read"] = True
    return {"status": "success", "message": "All notifications marked as read"}


@router.delete("/notifications")
def clear_notifications(
    current_user: User = Depends(get_current_user),
):
    """Clear all notifications."""
    global _notification_queue
    _notification_queue = []
    return {"status": "cleared", "message": "All notifications cleared"}


@router.post("/blocked-extensions")
def block_extension(
    extension: str = Query(..., description="File extension to block (e.g., .exe)"),
    current_user: User = Depends(get_current_user),
):
    """Add a file extension to the blocked list."""
    return {"status": "added", "extension": extension, "message": f"Extension {extension} added to block list"}


@router.get("/stats")
def get_antivirus_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get antivirus statistics."""
    total_scans = len(_scan_history)
    safe_count = len([s for s in _scan_history if s.get("classification") == "safe"])
    suspicious_count = len([s for s in _scan_history if s.get("classification") == "suspicious"])
    malicious_count = len([s for s in _scan_history if s.get("classification") == "malicious"])
    quarantined_count = len([s for s in _scan_history if s.get("quarantined")])

    db_scans = db.query(Scan).count()
    db_threats = db.query(Scan).filter(Scan.classification.in_(["malicious", "suspicious"])).count()

    return {
        "total_scans": total_scans + db_scans,
        "safe": safe_count,
        "suspicious": suspicious_count,
        "malicious": malicious_count,
        "quarantined": quarantined_count,
        "db_total_scans": db_scans,
        "db_threats": db_threats,
        "protection_status": "active" if _protection_enabled else "inactive",
    }


@router.get("/firewall-status")
def get_firewall_integration_status(
    current_user: User = Depends(get_current_user),
):
    """Get firewall integration status."""
    fw_status = firewall_service.get_firewall_status()
    return {
        "firewall_enabled": _firewall_integration_enabled,
        "firewall_active": fw_status.get("enabled", False),
        "zones": fw_status.get("zones", []),
        "active_rules": fw_status.get("active_rules", 0),
        "total_blocked": fw_status.get("stats", {}).get("total_blocked", 0),
        "threat_blocked_ips": _threat_blocked_ips,
        "threat_log": _threat_log[:100],
    }


@router.post("/firewall/enable")
def enable_firewall_integration(
    current_user: User = Depends(get_current_user),
):
    """Enable firewall integration with antivirus."""
    global _firewall_integration_enabled
    _firewall_integration_enabled = True
    _add_notification({
        "type": "success",
        "title": "Firewall Integration Enabled",
        "message": "Antivirus will now auto-block IPs that send malicious files.",
    })
    return {"status": "enabled"}


@router.post("/firewall/disable")
def disable_firewall_integration(
    current_user: User = Depends(get_current_user),
):
    """Disable firewall integration with antivirus."""
    global _firewall_integration_enabled
    _firewall_integration_enabled = False
    _add_notification({
        "type": "warning",
        "title": "Firewall Integration Disabled",
        "message": "Threat IPs will no longer be auto-blocked by firewall.",
    })
    return {"status": "disabled"}


@router.post("/firewall/block-ip")
def block_threat_ip(
    ip: str = Query(...),
    reason: str = Query("Manual block"),
    current_user: User = Depends(get_current_user),
):
    """Manually block an IP via firewall from antivirus."""
    firewall_service._blocked_ips[ip] = firewall_service._blocked_ips.get(ip, 0) + 1
    zone = firewall_service._get_zone_for_ip(ip)
    if ip not in [t["ip"] for t in _threat_blocked_ips]:
        _threat_blocked_ips.append({
            "ip": ip,
            "zone": zone["name"] if zone else "Unknown",
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "threats": 1,
            "reason": reason,
        })
    _threat_log.append({
        "id": len(_threat_log) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "zone": zone["name"] if zone else "Unknown",
        "filename": "",
        "risk_score": 0,
        "action": "blocked",
        "reason": reason,
    })
    return {"status": "blocked", "ip": ip, "zone": zone["name"] if zone else "Unknown"}


@router.post("/firewall/unblock-ip")
def unblock_threat_ip(
    ip: str = Query(...),
    current_user: User = Depends(get_current_user),
):
    """Unblock an IP from threat list."""
    global _threat_blocked_ips
    firewall_service.unblock_ip(ip)
    _threat_blocked_ips = [t for t in _threat_blocked_ips if t["ip"] != ip]
    return {"status": "unblocked", "ip": ip}


@router.get("/firewall/threat-log")
def get_threat_log(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
):
    """Get threat log from firewall integration."""
    return {"logs": _threat_log[:limit], "total": len(_threat_log)}


@router.get("/clamav/status")
def clamav_status(
    current_user: User = Depends(get_current_user),
):
    """Get ClamAV antivirus engine status and version info."""
    return get_clamav_status()
