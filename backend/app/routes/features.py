import os
import json
import csv
import io
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse, Response
from sqlalchemy.orm import Session
from ..database import get_db
from ..security.auth import get_current_user
from ..models.models import User
from ..services import webhook_service, scheduler_service, health_service, export_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Advanced Features"])


@router.get("/health/system")
def system_health(
    current_user: User = Depends(get_current_user),
):
    """Get comprehensive system health information."""
    return health_service.get_system_health()


@router.get("/health/public")
def system_health_public():
    """Get system health without authentication (for real-time updates)."""
    return health_service.get_system_health()


@router.get("/webhooks/status")
def webhook_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get webhook configuration status."""
    return webhook_service.get_webhook_status_db(db)


@router.post("/webhooks/save")
def save_webhook_config(
    slack: Optional[str] = None,
    discord: Optional[str] = None,
    custom: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Save webhook URLs."""
    webhook_service.save_webhook_urls(db, slack=slack, discord=discord, custom=custom)
    return {"status": "saved", "webhooks": webhook_service.get_webhook_status_db(db)}


@router.post("/webhooks/test")
def test_webhooks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Send a test alert to all configured webhooks."""
    urls = webhook_service.get_webhook_urls(db)
    result = {
        "slack": webhook_service.send_slack_alert(
            "Test Alert", "This is a test alert from MFDS", "info", url=urls["slack"]
        ),
        "discord": webhook_service.send_discord_alert(
            "Test Alert", "This is a test alert from MFDS", "info", url=urls["discord"]
        ),
        "custom": webhook_service.send_custom_webhook(
            "Test Alert", "This is a test alert from MFDS", "info", url=urls["custom"]
        ),
    }
    return {"status": "sent", "results": result}


@router.get("/scheduler/jobs")
def get_scheduled_scans(current_user: User = Depends(get_current_user)):
    """Get all scheduled scan jobs (admin only)."""
    jobs = scheduler_service.get_scheduled_scans()
    serializable_jobs = []
    for job in jobs:
        sj = {k: v for k, v in job.items()}
        for key in ("created_at", "next_run", "last_run"):
            if sj.get(key):
                sj[key] = sj[key].isoformat()
        serializable_jobs.append(sj)
    return {"jobs": serializable_jobs}


@router.get("/scheduler/common-paths")
def get_common_paths(current_user: User = Depends(get_current_user)):
    """Get common scan folder paths with resolved usernames (admin only)."""
    home = os.path.expanduser("~")
    paths = []
    for name, sub in [("Downloads", "Downloads"), ("Desktop", "Desktop"), ("Documents", "Documents")]:
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            paths.append({"label": name, "path": p, "exists": True})
        else:
            paths.append({"label": name, "path": p, "exists": False})
    for name, p in [("Temp", "C:\\Windows\\Temp"), ("Program Files", "C:\\Program Files")]:
        paths.append({"label": name, "path": p, "exists": os.path.isdir(p)})
    return {"paths": paths}


@router.post("/scheduler/add")
def add_scheduled_scan(
    folder_path: str = Query(..., description="Folder path to scan"),
    interval_minutes: int = Query(60, ge=10, description="Scan interval in minutes"),
    name: str = Query("", description="Job name"),
    current_user: User = Depends(get_current_user),
):
    """Add a new scheduled scan (admin only)."""
    return scheduler_service.add_scheduled_scan(folder_path, interval_minutes, name)


@router.delete("/scheduler/{job_id}")
def remove_scheduled_scan(
    job_id: int,
    current_user: User = Depends(get_current_user),
):
    """Remove a scheduled scan job (admin only)."""
    return scheduler_service.remove_scheduled_scan(job_id)


@router.post("/scheduler/{job_id}/toggle")
def toggle_scheduled_scan(
    job_id: int,
    enabled: bool = Query(...),
    current_user: User = Depends(get_current_user),
):
    """Enable or disable a scheduled scan (admin only)."""
    return scheduler_service.toggle_scheduled_scan(job_id, enabled)


@router.get("/export/scans/csv")
def export_scans_csv(
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export all scans as CSV."""
    csv_data = export_service.export_scans_csv(db, limit)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_results.csv"},
    )


@router.get("/export/scans/json")
def export_scans_json(
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export all scans as JSON."""
    json_data = export_service.export_scans_json(db, limit)
    return Response(
        content=json.dumps(json_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=scan_results.json"},
    )


@router.get("/export/threats/csv")
def export_threats_csv(
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export threats only as CSV."""
    csv_data = export_service.export_threats_csv(db, limit)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threats.csv"},
    )


@router.get("/export/quarantine/csv")
def export_quarantine_csv(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export quarantine records as CSV."""
    from ..models.models import QuarantineItem, File as FileModel
    items = db.query(QuarantineItem).order_by(QuarantineItem.quarantine_date.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Filename", "Hash", "Status", "Quarantine Date"])
    for item in items:
        file_record = db.query(FileModel).filter(FileModel.id == item.file_id).first()
        writer.writerow([
            item.id,
            item.original_filename,
            item.file_hash or "",
            item.status,
            item.quarantine_date.isoformat() if item.quarantine_date else "",
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=quarantine.csv"},
    )


@router.get("/export/logs/csv")
def export_logs_csv(
    limit: int = Query(5000, ge=1, le=50000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export security logs as CSV."""
    from ..models.models import AuditLog
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User ID", "Action", "Details", "Result", "Timestamp"])
    for log in logs:
        writer.writerow([
            log.id,
            log.user_id or "",
            log.action,
            log.details or "",
            log.result or "",
            log.timestamp.isoformat() if log.timestamp else "",
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_logs.csv"},
    )


@router.get("/export/scans/excel")
def export_scans_excel(
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export scans as Excel file."""
    try:
        from openpyxl import Workbook
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    from ..models.models import Scan, File as FileModel

    wb = Workbook()
    ws = wb.active
    ws.title = "Scan Results"
    headers = ["Scan ID", "Filename", "File Size", "MD5", "SHA256", "Risk Score", "Classification", "Entropy", "Scan Date"]
    ws.append(headers)

    scans = db.query(Scan).order_by(Scan.scan_date.desc()).limit(limit).all()
    for scan in scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        ws.append([
            scan.id,
            file_record.original_filename if file_record else "Unknown",
            file_record.file_size if file_record else 0,
            file_record.md5 if file_record else "",
            file_record.sha256 if file_record else "",
            scan.risk_score,
            scan.classification,
            round(scan.entropy, 4),
            scan.scan_date.isoformat() if scan.scan_date else "",
        ])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=scan_results.xlsx"},
    )


@router.get("/export/threats/excel")
def export_threats_excel(
    limit: int = Query(1000, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export threats as Excel file."""
    try:
        from openpyxl import Workbook
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    from ..models.models import Scan, File as FileModel

    wb = Workbook()
    ws = wb.active
    ws.title = "Threats"
    headers = ["Scan ID", "Filename", "Risk Score", "Classification", "Detection Reasons", "Scan Date"]
    ws.append(headers)

    scans = db.query(Scan).filter(
        Scan.classification.in_(["malicious", "suspicious"])
    ).order_by(Scan.scan_date.desc()).limit(limit).all()

    for scan in scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        ws.append([
            scan.id,
            file_record.original_filename if file_record else "Unknown",
            scan.risk_score,
            scan.classification,
            scan.detection_reasons or "",
            scan.scan_date.isoformat() if scan.scan_date else "",
        ])

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    return Response(
        content=output.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=threats.xlsx"},
    )
