import os
import json
import uuid
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog
from ..security.auth import get_current_user
from ..scanner.file_analyzer import analyze_file
from ..scanner.hash_calculator import calculate_hashes
from ..scanner.mime_detector import detect_mime_type
from ..services.virustotal import query_hash
from ..services.alert_service import create_alert
from ..utils.helpers import sanitize_filename

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/usb-scanner", tags=["USB Scanner"])


def get_removable_drives() -> List[dict]:
    """Detect removable drives based on the operating system."""
    drives = []
    system = platform.system()

    try:
        if system == "Windows":
            import string
            import ctypes

            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive_path = f"{letter}:\\"
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    if drive_type == 2:  # DRIVE_REMOVABLE
                        try:
                            free_bytes = ctypes.c_ulonglong(0)
                            total_bytes = ctypes.c_ulonglong(0)
                            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                                drive_path,
                                None,
                                ctypes.pointer(total_bytes),
                                ctypes.pointer(free_bytes)
                            )
                            total_gb = total_bytes.value / (1024**3)
                            free_gb = free_bytes.value / (1024**3)
                            used_gb = total_gb - free_gb

                            file_count = sum(len(files) for _, _, files in os.walk(drive_path))

                            drives.append({
                                "id": len(drives) + 1,
                                "name": f"USB Drive ({letter}:)",
                                "path": drive_path,
                                "size": f"{total_gb:.1f} GB",
                                "used": f"{used_gb:.1f} GB",
                                "free": f"{free_gb:.1f} GB",
                                "type": "Removable",
                                "files": file_count,
                                "status": "connected",
                            })
                        except Exception as e:
                            logger.warning(f"Could not get details for drive {letter}: {e}")
                            drives.append({
                                "id": len(drives) + 1,
                                "name": f"USB Drive ({letter}:)",
                                "path": drive_path,
                                "size": "Unknown",
                                "used": "Unknown",
                                "free": "Unknown",
                                "type": "Removable",
                                "files": 0,
                                "status": "connected",
                            })
                bitmask >>= 1

        elif system == "Linux":
            result = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,RM"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    if device.get("rm") == True and device.get("mountpoint"):
                        mount_point = device["mountpoint"]
                        try:
                            stat = os.statvfs(mount_point)
                            total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
                            free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
                            used_gb = total_gb - free_gb
                            file_count = sum(len(files) for _, _, files in os.walk(mount_point))
                            drives.append({
                                "id": len(drives) + 1,
                                "name": f"USB Drive ({device['name']})",
                                "path": mount_point,
                                "size": f"{total_gb:.1f} GB",
                                "used": f"{used_gb:.1f} GB",
                                "free": f"{free_gb:.1f} GB",
                                "type": "Removable",
                                "files": file_count,
                                "status": "connected",
                            })
                        except Exception as e:
                            logger.warning(f"Could not get details for {mount_point}: {e}")

        elif system == "Darwin":
            result = subprocess.run(
                ["diskutil", "list", "-plist"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                plist = __import__("plistlib").loads(result.stdout.encode())
                for disk in plist.get("AllDisksAndPartitions", []):
                    if disk.get("RemovableMedia") or disk.get("BusProtocol") == "USB":
                        for partition in disk.get("Partitions", []):
                            mount_point = partition.get("MountPoint")
                            if mount_point and os.path.exists(mount_point):
                                try:
                                    stat = os.statvfs(mount_point)
                                    total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
                                    free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
                                    used_gb = total_gb - free_gb
                                    file_count = sum(len(files) for _, _, files in os.walk(mount_point))
                                    drives.append({
                                        "id": len(drives) + 1,
                                        "name": f"USB Drive ({partition.get('VolumeName', 'Untitled')})",
                                        "path": mount_point,
                                        "size": f"{total_gb:.1f} GB",
                                        "used": f"{used_gb:.1f} GB",
                                        "free": f"{free_gb:.1f} GB",
                                        "type": "Removable",
                                        "files": file_count,
                                        "status": "connected",
                                    })
                                except Exception as e:
                                    logger.warning(f"Could not get details for {mount_point}: {e}")

    except Exception as e:
        logger.error(f"Error detecting USB drives: {e}")

    return drives


@router.get("/drives")
def list_usb_drives(
    current_user: User = Depends(get_current_user),
):
    """List all connected USB/removable drives."""
    drives = get_removable_drives()
    return {"drives": drives, "total": len(drives)}


@router.get("/files")
def list_usb_files(
    drive_path: str,
    current_user: User = Depends(get_current_user),
):
    """List all files on a USB drive."""
    if not os.path.exists(drive_path):
        raise HTTPException(status_code=404, detail=f"Drive not found: {drive_path}")

    skip_dirs = {"$RECYCLE.BIN", "System Volume Information", ".Trash-1000"}
    all_files = []

    try:
        for root, dirs, files in os.walk(drive_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                full_path = os.path.join(root, filename)
                try:
                    stat = os.stat(full_path)
                    size = stat.st_size
                    modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
                except OSError:
                    size = 0
                    modified = None

                ext = os.path.splitext(filename)[1].lower()
                all_files.append({
                    "name": filename,
                    "path": full_path,
                    "size": size,
                    "size_human": f"{size / 1024:.1f} KB" if size < 1048576 else f"{size / 1048576:.1f} MB",
                    "extension": ext,
                    "modified": modified,
                })
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied accessing drive")

    return {
        "drive_path": drive_path,
        "total_files": len(all_files),
        "files": all_files[:500],
    }


@router.post("/scan")
def scan_usb_drive(
    drive_path: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Scan files on a USB drive for threats."""
    if not os.path.exists(drive_path):
        raise HTTPException(status_code=404, detail=f"Drive not found: {drive_path}")

    if not os.path.isdir(drive_path):
        raise HTTPException(status_code=400, detail="Path is not a directory")

    suspicious_extensions = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".sh",
        ".doc", ".docx", ".pdf", ".zip", ".rar", ".scr", ".com", ".pif",
        ".msi", ".hta", ".cpl", ".wsf", ".reg", ".sys", ".drv", ".tmp",
        ".dat", ".bin", ".ini", ".inf", ".autorun", ".lnk", ".pif",
    }

    skip_dirs = {"$RECYCLE.BIN", "System Volume Information", ".Trash-1000"}

    files_to_scan = []
    try:
        for root, dirs, files in os.walk(drive_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for filename in files:
                full_path = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()
                try:
                    if os.path.getsize(full_path) == 0:
                        continue
                except OSError:
                    continue
                if ext in suspicious_extensions or filename.lower() in {
                    "autorun.inf", "setup.exe", "install.exe", "run.bat",
                    "start.bat", "open.bat", "launch.exe",
                }:
                    files_to_scan.append(full_path)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied accessing drive")

    if not files_to_scan:
        return {
            "message": "No suspicious files found on the drive",
            "files_found": 0,
            "files_scanned": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "results": [],
        }

    files_to_scan = files_to_scan[:100]

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
                create_alert(analysis, db, current_user.id)

            results.append({
                "original_path": file_path,
                "filename": safe_name,
                "file_id": file_record.id,
                "scan_id": scan.id,
                "risk_score": scan.risk_score,
                "classification": scan.classification,
                "reasons": analysis.get("detection_reasons", []),
                "file_size": file_size,
                "extension": ext,
                "mime_type": mime_type,
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "entropy": analysis.get("entropy", 0),
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
        action="usb_scan",
        details=f"Scanned {len(results)} files from USB drive {drive_path}",
        result="success",
    )
    db.add(log)
    db.commit()

    malicious_count = sum(1 for r in results if r.get("classification") == "malicious")
    suspicious_count = sum(1 for r in results if r.get("classification") == "suspicious")

    return {
        "drive_path": drive_path,
        "files_found": len(files_to_scan),
        "files_scanned": len(results),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "results": results,
    }
