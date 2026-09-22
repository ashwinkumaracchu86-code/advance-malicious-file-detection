import os
import json
import logging
import time
import asyncio
import threading
from typing import Optional, List
from datetime import datetime, timezone

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models.models import File, Scan, AuditLog
from ..scanner.file_analyzer import analyze_file
from ..utils.helpers import sanitize_filename
from .virustotal import query_hash
from .alert_service import create_alert
from . import quarantine_service

logger = logging.getLogger(__name__)

_monitoring_active = False
_observer: Optional[object] = None
_monitor_notifications: List[dict] = []
_monitor_scan_results: List[dict] = []
_monitor_lock = threading.Lock()
_auto_quarantine = True


def _add_monitor_notification(notification: dict):
    """Add a notification to the monitor notification queue and broadcast via WebSocket."""
    with _monitor_lock:
        notification["id"] = len(_monitor_notifications) + 1
        notification["timestamp"] = datetime.now(timezone.utc).isoformat()
        notification["read"] = False
        _monitor_notifications.insert(0, notification)
        if len(_monitor_notifications) > 100:
            _monitor_notifications.pop()
    try:
        from .ws_manager import manager
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(manager.broadcast_notification(notification))
        else:
            loop.run_until_complete(manager.broadcast_notification(notification))
    except Exception:
        pass


class MaliciousFileHandler(FileSystemEventHandler):
    """Watchdog handler for processing new/modified files."""

    def __init__(self):
        super().__init__()
        self.processed_files = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_file(event.src_path)

    def _process_file(self, file_path: str):
        if file_path in self.processed_files:
            return
        self.processed_files.add(file_path)

        time.sleep(1)

        if not os.path.isfile(file_path):
            return

        filename = os.path.basename(file_path)
        logger.info(f"Processing monitored file: {filename}")

        _add_monitor_notification({
            "type": "info",
            "title": "New File Detected",
            "message": f"Scanning new file: {filename}",
            "filename": filename,
        })

        db = SessionLocal()
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                logger.info(f"Skipping empty file: {filename}")
                return

            from ..scanner.hash_calculator import calculate_hashes
            from ..scanner.mime_detector import detect_mime_type

            hashes = calculate_hashes(file_path)
            mime_type = detect_mime_type(file_path)
            ext = os.path.splitext(filename)[1].lower()

            safe_name = sanitize_filename(filename)
            stored_filename = f"{hashes['sha256'][:16]}_{safe_name}"

            file_record = File(
                original_filename=filename,
                stored_filename=stored_filename,
                file_path=file_path,
                file_size=file_size,
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                mime_type=mime_type,
                extension=ext,
                upload_date=None,
            )
            db.add(file_record)
            db.commit()
            db.refresh(file_record)

            vt_results = query_hash(hashes["sha256"])
            analysis = analyze_file(file_path, vt_results)
            analysis["original_filename"] = filename

            scan = Scan(
                file_id=file_record.id,
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

            classification = analysis.get("classification", "unknown")
            risk_score = analysis.get("risk_score", 0)

            scan_result = {
                "filename": filename,
                "risk_score": risk_score,
                "classification": classification,
                "scan_id": scan.id,
                "file_id": file_record.id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            with _monitor_lock:
                _monitor_scan_results.insert(0, scan_result)
                if len(_monitor_scan_results) > 200:
                    _monitor_scan_results.pop()

            try:
                from .ws_manager import manager
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(manager.broadcast_scan_result(scan_result))
                else:
                    loop.run_until_complete(manager.broadcast_scan_result(scan_result))
            except Exception:
                pass

            if classification in ("malicious", "suspicious"):
                create_alert(analysis, db)
                logger.warning(
                    f"Threat detected in monitored file: {filename} "
                    f"(Classification: {classification}, Score: {risk_score})"
                )

                severity = "MALICIOUS" if classification == "malicious" else "SUSPICIOUS"
                _add_monitor_notification({
                    "type": "threat" if classification == "malicious" else "warning",
                    "title": f"{severity} File Detected",
                    "message": f'"{filename}" is {classification} (Score: {risk_score}/100)',
                    "filename": filename,
                    "risk_score": risk_score,
                    "classification": classification,
                })

                if _auto_quarantine:
                    quarantine_service.quarantine_file(
                        file_path=file_path,
                        original_filename=filename,
                        file_hash=hashes["sha256"],
                        db=db,
                    )
                    scan_result["quarantined"] = True
                    _add_monitor_notification({
                        "type": "threat",
                        "title": "Auto-Quarantined",
                        "message": f'"{filename}" has been quarantined.',
                        "filename": filename,
                    })
            else:
                logger.info(f"File scanned clean: {filename}")
                _add_monitor_notification({
                    "type": "success",
                    "title": "File Scan Complete",
                    "message": f'"{filename}" is safe. No threats detected.',
                    "filename": filename,
                    "risk_score": risk_score,
                    "classification": classification,
                })

        except Exception as e:
            logger.error(f"Error processing monitored file {filename}: {e}")
            _add_monitor_notification({
                "type": "error",
                "title": "Scan Error",
                "message": f"Failed to scan {filename}: {str(e)}",
                "filename": filename,
            })
            db.rollback()
        finally:
            db.close()


def start_monitoring(folder_path: str, db: Optional[Session] = None) -> dict:
    """Start monitoring a folder for new files."""
    global _monitoring_active, _observer

    if not WATCHDOG_AVAILABLE:
        return {
            "status": "error",
            "message": "watchdog library not installed. Install with: pip install watchdog",
        }

    if _monitoring_active:
        return {
            "status": "already_active",
            "message": "Monitoring is already active",
        }

    if not os.path.isdir(folder_path):
        return {
            "status": "error",
            "message": f"Folder does not exist: {folder_path}",
        }

    try:
        handler = MaliciousFileHandler()
        _observer = Observer()
        _observer.schedule(handler, folder_path, recursive=False)
        _observer.daemon = True
        _observer.start()
        _monitoring_active = True

        _add_monitor_notification({
            "type": "success",
            "title": "Monitoring Started",
            "message": f"Watching folder: {folder_path}",
        })

        logger.info(f"Started monitoring folder: {folder_path}")

        return {
            "status": "started",
            "folder": folder_path,
            "message": f"Monitoring started for: {folder_path}",
        }

    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return {
            "status": "error",
            "message": str(e),
        }


def stop_monitoring() -> dict:
    """Stop the folder monitoring."""
    global _monitoring_active, _observer

    if not _monitoring_active or _observer is None:
        return {
            "status": "not_active",
            "message": "Monitoring is not currently active",
        }

    try:
        _observer.stop()
        _observer.join(timeout=5)
        _monitoring_active = False
        _observer = None

        _add_monitor_notification({
            "type": "warning",
            "title": "Monitoring Stopped",
            "message": "Folder monitoring has been stopped.",
        })

        logger.info("Folder monitoring stopped.")
        return {
            "status": "stopped",
            "message": "Monitoring stopped",
        }

    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        return {
            "status": "error",
            "message": str(e),
        }


def get_monitoring_status() -> dict:
    """Get the current monitoring status."""
    return {
        "active": _monitoring_active,
        "watchdog_available": WATCHDOG_AVAILABLE,
        "notifications": _monitor_notifications[:20],
        "scan_results": _monitor_scan_results[:20],
    }


def get_monitor_notifications(limit: int = 50) -> List[dict]:
    """Get monitor notifications."""
    with _monitor_lock:
        return _monitor_notifications[:limit]


def get_monitor_scan_results(limit: int = 50) -> List[dict]:
    """Get monitor scan results."""
    with _monitor_lock:
        return _monitor_scan_results[:limit]
