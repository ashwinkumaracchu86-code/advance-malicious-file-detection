import os
import json
import logging
import threading
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_scheduled_scans: List[Dict[str, Any]] = []
_scheduler_thread: Optional[threading.Thread] = None
_scheduler_running = False


def _run_scheduler():
    """Background thread that checks and runs scheduled scans."""
    global _scheduler_running
    _scheduler_running = True

    while _scheduler_running:
        now = datetime.now(timezone.utc)
        for scan_job in _scheduled_scans:
            if not scan_job.get("enabled", True):
                continue

            next_run = scan_job.get("next_run")
            if next_run and now >= next_run:
                _execute_scheduled_scan(scan_job)
                _update_next_run(scan_job)

        time.sleep(30)


def _execute_scheduled_scan(scan_job: Dict[str, Any]):
    """Execute a scheduled scan."""
    from . import quarantine_service
    from ..scanner.file_analyzer import analyze_file
    from ..scanner.hash_calculator import calculate_hashes
    from ..scanner.mime_detector import detect_mime_type
    from ..models.models import File, Scan
    from ..database import SessionLocal

    folder_path = scan_job.get("folder_path", "")
    if not os.path.isdir(folder_path):
        logger.error(f"Scheduled scan folder not found: {folder_path}")
        return

    db = SessionLocal()
    try:
        scan_count = 0
        threat_count = 0

        for fname in os.listdir(folder_path):
            fpath = os.path.join(folder_path, fname)
            if not os.path.isfile(fpath):
                continue

            try:
                hashes = calculate_hashes(fpath)
                mime_type = detect_mime_type(fpath)
                ext = os.path.splitext(fname)[1].lower()
                file_size = os.path.getsize(fpath)

                file_record = File(
                    original_filename=fname,
                    stored_filename=f"{hashes['sha256'][:16]}_{fname}",
                    file_path=fpath,
                    file_size=file_size,
                    md5=hashes["md5"],
                    sha1=hashes["sha1"],
                    sha256=hashes["sha256"],
                    mime_type=mime_type,
                    extension=ext,
                )
                db.add(file_record)
                db.commit()
                db.refresh(file_record)

                analysis = analyze_file(fpath)
                scan = Scan(
                    file_id=file_record.id,
                    risk_score=analysis.get("risk_score", 0),
                    classification=analysis.get("classification", "unknown"),
                    entropy=analysis.get("entropy", 0),
                    suspicious_strings=json.dumps(analysis.get("suspicious_strings", []), default=str),
                    detection_reasons=json.dumps(analysis.get("detection_reasons", []), default=str),
                )
                db.add(scan)
                db.commit()

                scan_count += 1
                if analysis.get("classification") in ("malicious", "suspicious"):
                    threat_count += 1

            except Exception as e:
                logger.error(f"Scheduled scan error for {fname}: {e}")
                db.rollback()

        scan_job["last_run"] = datetime.now(timezone.utc)
        scan_job["last_result"] = {"scanned": scan_count, "threats": threat_count}
        logger.info(f"Scheduled scan completed: {scan_count} files, {threat_count} threats")

    finally:
        db.close()


def _update_next_run(scan_job: Dict[str, Any]):
    """Calculate next run time based on interval."""
    interval_minutes = scan_job.get("interval_minutes", 60)
    scan_job["next_run"] = datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)


def start_scheduler():
    """Start the background scheduler thread."""
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_thread = threading.Thread(target=_run_scheduler, daemon=True)
    _scheduler_thread.start()
    logger.info("Scheduler thread started")


def stop_scheduler():
    """Stop the background scheduler thread."""
    global _scheduler_running
    _scheduler_running = False
    logger.info("Scheduler stopped")


def add_scheduled_scan(folder_path: str, interval_minutes: int = 60, name: str = "") -> Dict[str, Any]:
    """Add a new scheduled scan job."""
    if not os.path.isdir(folder_path):
        return {"error": f"Folder not found: {folder_path}"}

    scan_job = {
        "id": len(_scheduled_scans) + 1,
        "name": name or f"Scan: {os.path.basename(folder_path)}",
        "folder_path": folder_path,
        "interval_minutes": interval_minutes,
        "enabled": True,
        "created_at": datetime.now(timezone.utc),
        "next_run": datetime.now(timezone.utc) + timedelta(minutes=interval_minutes),
        "last_run": None,
        "last_result": None,
    }

    _scheduled_scans.append(scan_job)
    start_scheduler()

    return {"status": "added", "job": scan_job}


def remove_scheduled_scan(job_id: int) -> Dict[str, Any]:
    """Remove a scheduled scan job."""
    global _scheduled_scans
    for i, job in enumerate(_scheduled_scans):
        if job["id"] == job_id:
            removed = _scheduled_scans.pop(i)
            return {"status": "removed", "job": removed}
    return {"error": f"Job {job_id} not found"}


def toggle_scheduled_scan(job_id: int, enabled: bool) -> Dict[str, Any]:
    """Enable or disable a scheduled scan job."""
    for job in _scheduled_scans:
        if job["id"] == job_id:
            job["enabled"] = enabled
            return {"status": "updated", "job": job}
    return {"error": f"Job {job_id} not found"}


def get_scheduled_scans() -> List[Dict[str, Any]]:
    """Get all scheduled scan jobs."""
    return _scheduled_scans
