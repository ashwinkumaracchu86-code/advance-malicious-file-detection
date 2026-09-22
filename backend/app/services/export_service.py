import csv
import json
import io
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def export_scans_csv(db: Session, limit: int = 1000) -> str:
    """Export scan results as CSV string."""
    from ..models.models import Scan, File as FileModel

    scans = (
        db.query(Scan)
        .order_by(Scan.scan_date.desc())
        .limit(limit)
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Filename", "File Size", "MD5", "SHA256",
        "Risk Score", "Classification", "Entropy",
        "Suspicious Strings", "Detection Reasons", "VT Detections",
        "Scan Date"
    ])

    for scan in scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        writer.writerow([
            scan.id,
            file_record.original_filename if file_record else "Unknown",
            file_record.file_size if file_record else 0,
            file_record.md5 if file_record else "",
            file_record.sha256 if file_record else "",
            scan.risk_score,
            scan.classification,
            scan.entropy,
            scan.suspicious_strings,
            scan.detection_reasons,
            scan.vt_positives,
            scan.scan_date.isoformat() if scan.scan_date else "",
        ])

    return output.getvalue()


def export_scans_json(db: Session, limit: int = 1000) -> List[Dict[str, Any]]:
    """Export scan results as JSON-serializable list."""
    from ..models.models import Scan, File as FileModel

    scans = (
        db.query(Scan)
        .order_by(Scan.scan_date.desc())
        .limit(limit)
        .all()
    )

    results = []
    for scan in scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        results.append({
            "scan_id": scan.id,
            "filename": file_record.original_filename if file_record else "Unknown",
            "file_size": file_record.file_size if file_record else 0,
            "md5": file_record.md5 if file_record else "",
            "sha256": file_record.sha256 if file_record else "",
            "risk_score": scan.risk_score,
            "classification": scan.classification,
            "entropy": scan.entropy,
            "suspicious_strings": scan.suspicious_strings,
            "detection_reasons": scan.detection_reasons,
            "vt_detections": scan.vt_positives,
            "scan_date": scan.scan_date.isoformat() if scan.scan_date else "",
        })

    return results


def export_threats_csv(db: Session, limit: int = 1000) -> str:
    """Export only threats (malicious/suspicious) as CSV."""
    from ..models.models import Scan, File as FileModel

    scans = (
        db.query(Scan)
        .filter(Scan.classification.in_(["malicious", "suspicious"]))
        .order_by(Scan.scan_date.desc())
        .limit(limit)
        .all()
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Filename", "Risk Score", "Classification",
        "Detection Reasons", "Scan Date"
    ])

    for scan in scans:
        file_record = db.query(FileModel).filter(FileModel.id == scan.file_id).first()
        writer.writerow([
            scan.id,
            file_record.original_filename if file_record else "Unknown",
            scan.risk_score,
            scan.classification,
            scan.detection_reasons,
            scan.scan_date.isoformat() if scan.scan_date else "",
        ])

    return output.getvalue()
