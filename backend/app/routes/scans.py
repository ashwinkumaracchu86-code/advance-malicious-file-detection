import json
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog
from ..schemas.schemas import ScanResponse, FileResponse
from ..security.auth import get_current_user
from ..scanner.file_analyzer import analyze_file
from ..services.virustotal import query_hash

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scans"])


@router.post("/scan/{file_id}", response_model=ScanResponse)
def trigger_scan(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger a scan for a specific file."""
    file_record = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    import os
    if not os.path.isfile(file_record.file_path):
        raise HTTPException(status_code=404, detail="File not found on disk")

    vt_results = query_hash(file_record.sha256)
    analysis = analyze_file(file_record.file_path, vt_results)
    analysis["original_filename"] = file_record.original_filename

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

    log = AuditLog(
        user_id=current_user.id,
        action="file_scan",
        details=f"Scanned {file_record.original_filename}. Score: {scan.risk_score}, Classification: {scan.classification}",
        result="success",
    )
    db.add(log)
    db.commit()

    return ScanResponse.model_validate(scan)


@router.get("/scans", response_model=dict)
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    classification: Optional[str] = None,
    sort_by: str = Query("scan_date", pattern="^(scan_date|risk_score|classification)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scans with pagination, search, filter, and sort."""
    query = db.query(Scan)

    if classification:
        query = query.filter(Scan.classification == classification)

    if search:
        query = query.join(FileModel, Scan.file_id == FileModel.id).filter(
            FileModel.original_filename.contains(search)
        )

    sort_column = getattr(Scan, sort_by, Scan.scan_date)
    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    total = query.count()
    scans = query.offset(skip).limit(limit).all()

    results = []
    for scan in scans:
        scan_data = ScanResponse.model_validate(scan)
        if scan.file:
            scan_data.file = FileResponse.model_validate(scan.file)
        results.append(scan_data)

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "scans": [s.model_dump() for s in results],
    }


@router.get("/scan/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan result by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = ScanResponse.model_validate(scan)
    if scan.file:
        scan_data.file = FileResponse.model_validate(scan.file)
    return scan_data
