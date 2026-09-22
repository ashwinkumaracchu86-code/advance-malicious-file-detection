import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, Integer
from ..database import get_db
from ..models.models import User, Scan, File as FileModel, AuditLog
from ..security.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("/dashboard")
def get_threat_dashboard(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get threat intelligence dashboard data."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    total_scans = db.query(Scan).filter(Scan.scan_date >= since).count()
    malicious_count = db.query(Scan).filter(
        Scan.scan_date >= since,
        Scan.classification == "malicious"
    ).count()
    suspicious_count = db.query(Scan).filter(
        Scan.scan_date >= since,
        Scan.classification == "suspicious"
    ).count()
    safe_count = db.query(Scan).filter(
        Scan.scan_date >= since,
        Scan.classification == "safe"
    ).count()

    risk_distribution = db.query(
        Scan.classification,
        func.count(Scan.id)
    ).filter(Scan.scan_date >= since).group_by(Scan.classification).all()

    daily_threats = db.query(
        func.date(Scan.scan_date).label("date"),
        func.count(Scan.id).label("count"),
        func.avg(Scan.risk_score).label("avg_risk")
    ).filter(
        Scan.scan_date >= since,
        Scan.classification.in_(["malicious", "suspicious"])
    ).group_by(func.date(Scan.scan_date)).order_by(func.date(Scan.scan_date)).all()

    top_risk_files = db.query(
        Scan, FileModel
    ).join(
        FileModel, Scan.file_id == FileModel.id
    ).filter(
        Scan.scan_date >= since
    ).order_by(desc(Scan.risk_score)).limit(10).all()

    high_risk_detections = []
    for scan, file_record in top_risk_files[:5]:
        detection_reasons = []
        try:
            detection_reasons = json.loads(scan.detection_reasons) if scan.detection_reasons else []
        except (json.JSONDecodeError, TypeError):
            pass

        high_risk_detections.append({
            "scan_id": scan.id,
            "filename": file_record.original_filename,
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "scan_date": str(scan.scan_date),
            "detection_reasons": detection_reasons[:3],
        })

    file_type_risks = db.query(
        FileModel.extension,
        func.count(Scan.id).label("scan_count"),
        func.avg(Scan.risk_score).label("avg_risk"),
        func.max(Scan.risk_score).label("max_risk")
    ).join(
        Scan, FileModel.id == Scan.file_id
    ).filter(
        Scan.scan_date >= since,
        FileModel.extension.isnot(None),
        FileModel.extension != ""
    ).group_by(FileModel.extension).order_by(desc("scan_count")).limit(10).all()

    threat_trend = []
    for row in daily_threats:
        threat_trend.append({
            "date": str(row.date),
            "count": row.count,
            "avg_risk": round(float(row.avg_risk), 1) if row.avg_risk else 0,
        })

    return {
        "summary": {
            "total_scans": total_scans,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "threat_rate": round((malicious_count + suspicious_count) / total_scans * 100, 1) if total_scans > 0 else 0,
        },
        "risk_distribution": {row[0]: row[1] for row in risk_distribution},
        "threat_trend": threat_trend,
        "high_risk_detections": high_risk_detections,
        "file_type_risks": [
            {
                "extension": row[0],
                "scan_count": row[1],
                "avg_risk": round(float(row[2]), 1) if row[2] else 0,
                "max_risk": round(float(row[3]), 1) if row[3] else 0,
            }
            for row in file_type_risks
        ],
        "top_yara_rules": [],
        "period_days": days,
    }


@router.get("/trends")
def get_threat_trends(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get daily threat trends for charts."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    daily_data = db.query(
        func.date(Scan.scan_date).label("date"),
        func.count(Scan.id).label("total"),
        func.sum(func.cast(Scan.classification == "malicious", Integer)).label("malicious"),
        func.sum(func.cast(Scan.classification == "suspicious", Integer)).label("suspicious"),
        func.sum(func.cast(Scan.classification == "safe", Integer)).label("safe"),
    ).filter(
        Scan.scan_date >= since
    ).group_by(func.date(Scan.scan_date)).order_by(func.date(Scan.scan_date)).all()

    trends = []
    for row in daily_data:
        trends.append({
            "date": str(row.date),
            "total": row.total,
            "malicious": row.malicious or 0,
            "suspicious": row.suspicious or 0,
            "safe": row.safe or 0,
        })

    return {"trends": trends, "period_days": days}


@router.get("/stats")
def get_threat_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get overall threat statistics."""
    total_scans = db.query(Scan).count()
    total_malicious = db.query(Scan).filter(Scan.classification == "malicious").count()
    total_suspicious = db.query(Scan).filter(Scan.classification == "suspicious").count()

    avg_risk = db.query(func.avg(Scan.risk_score)).scalar() or 0
    max_risk = db.query(func.max(Scan.risk_score)).scalar() or 0

    today = datetime.now(timezone.utc).date()
    today_scans = db.query(Scan).filter(func.date(Scan.scan_date) == today).count()
    today_threats = db.query(Scan).filter(
        func.date(Scan.scan_date) == today,
        Scan.classification.in_(["malicious", "suspicious"])
    ).count()

    return {
        "total_scans": total_scans,
        "total_malicious": total_malicious,
        "total_suspicious": total_suspicious,
        "average_risk_score": round(float(avg_risk), 1),
        "max_risk_score": round(float(max_risk), 1),
        "today_scans": today_scans,
        "today_threats": today_threats,
    }
