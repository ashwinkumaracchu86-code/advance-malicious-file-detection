from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models.models import Scan, File as FileModel, QuarantineItem
from ..schemas.schemas import DashboardStats
from ..security.auth import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/statistics", response_model=DashboardStats)
def get_statistics(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get dashboard statistics."""
    total_scans = db.query(Scan).count()
    total_files = db.query(FileModel).count()
    quarantined_count = db.query(QuarantineItem).filter(QuarantineItem.status == "quarantined").count()

    safe_count = db.query(Scan).filter(Scan.classification == "safe").count()
    low_risk_count = db.query(Scan).filter(Scan.classification == "low_risk").count()
    suspicious_count = db.query(Scan).filter(Scan.classification == "suspicious").count()
    malicious_count = db.query(Scan).filter(Scan.classification == "malicious").count()

    detection_percentage = 0.0
    if total_scans > 0:
        detected = suspicious_count + malicious_count
        detection_percentage = round((detected / total_scans) * 100, 2)

    recent_scans = (
        db.query(Scan)
        .order_by(Scan.scan_date.desc())
        .limit(10)
        .all()
    )
    recent_list = []
    for scan in recent_scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        recent_list.append({
            "id": scan.id,
            "filename": file_record.original_filename if file_record else "Unknown",
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
        })

    risk_distribution = {
        "safe": safe_count,
        "low_risk": low_risk_count,
        "suspicious": suspicious_count,
        "malicious": malicious_count,
    }

    file_type_stats = (
        db.query(FileModel.extension, func.count(FileModel.id))
        .group_by(FileModel.extension)
        .all()
    )
    file_type_distribution = {ext or "unknown": count for ext, count in file_type_stats}

    recent_dates = (
        db.query(Scan.scan_date)
        .filter(Scan.scan_date.isnot(None))
        .all()
    )
    daily_totals = {}
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).date()
    for (sd,) in recent_dates:
        try:
            if isinstance(sd, str):
                day = sd[:10]
            else:
                day = sd.date().isoformat()
        except Exception:
            continue
        try:
            day_date = datetime.fromisoformat(day).date()
        except Exception:
            continue
        if day_date >= cutoff:
            daily_totals[day] = daily_totals.get(day, 0) + 1
    daily_scans = [
        {"date": day, "count": count}
        for day, count in sorted(daily_totals.items())
    ]

    return DashboardStats(
        total_scans=total_scans,
        total_files=total_files,
        safe_count=safe_count + low_risk_count,
        suspicious_count=suspicious_count,
        malicious_count=malicious_count,
        quarantined_count=quarantined_count,
        detection_percentage=detection_percentage,
        recent_scans=recent_list,
        risk_distribution=risk_distribution,
        file_type_distribution=file_type_distribution,
        daily_scans=daily_scans,
    )
