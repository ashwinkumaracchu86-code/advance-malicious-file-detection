import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog
from ..schemas.schemas import ScanResponse, FileResponse
from ..security.auth import get_current_user
from ..security.ownership import owned_or_forbidden
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
    """Trigger a scan for a specific file (owner only)."""
    file_record = owned_or_forbidden(
        db.query(FileModel).filter(FileModel.id == file_id).first(),
        current_user,
        "uploaded_by",
    )

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

    scan_data = ScanResponse.model_validate(scan)
    scan_data.filename = file_record.original_filename
    scan_data.hash = file_record.sha256
    scan_data.sha256 = file_record.sha256
    scan_data.file_size = file_record.file_size
    scan_data.created_at = scan.scan_date.isoformat() if scan.scan_date else None
    scan_data.file = FileResponse.model_validate(file_record)
    return scan_data


@router.get("/scans", response_model=dict)
@router.get("/scan-history", response_model=dict)
@router.get("/api/scan-history", response_model=dict)
@router.get("/scans/history", response_model=dict)
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = None,
    classification: Optional[str] = None,
    sort_by: Optional[str] = Query("scan_date"),
    sort_order: Optional[str] = Query("desc"),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List the caller's own scans with pagination, search, filter, and sort (strictly isolated per user)."""
    query = db.query(Scan).filter(Scan.user_id == current_user.id)

    if classification and classification.lower() != "all":
        query = query.filter(Scan.classification == classification.lower())

    joined_file = False
    if search:
        query = query.join(FileModel, Scan.file_id == FileModel.id)
        joined_file = True
        query = query.filter(FileModel.original_filename.contains(search))

    if date_from:
        try:
            df = datetime.fromisoformat(date_from)
            query = query.filter(Scan.scan_date >= df)
        except Exception:
            pass

    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            if len(date_to) <= 10:
                dt = dt.replace(hour=23, minute=59, second=59)
            query = query.filter(Scan.scan_date <= dt)
        except Exception:
            pass

    clean_sort = (sort_by or "scan_date").lower()
    is_desc = sort_order == "desc" or clean_sort.startswith("-")
    clean_sort = clean_sort.lstrip("-")

    if clean_sort in ("created_at", "scan_date", "date"):
        sort_column = Scan.scan_date
    elif clean_sort in ("risk_score", "risk"):
        sort_column = Scan.risk_score
    elif clean_sort == "classification":
        sort_column = Scan.classification
    elif clean_sort == "filename":
        if not joined_file:
            query = query.join(FileModel, Scan.file_id == FileModel.id)
        sort_column = FileModel.original_filename
    else:
        sort_column = Scan.scan_date

    if is_desc:
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    total = query.count()
    scans = query.offset(skip).limit(limit).all()

    results = []
    for scan in scans:
        scan_dict = ScanResponse.model_validate(scan).model_dump()
        if scan.file:
            scan_dict["file"] = FileResponse.model_validate(scan.file).model_dump()
            scan_dict["filename"] = scan.file.original_filename
            scan_dict["sha256"] = scan.file.sha256
            scan_dict["hash"] = scan.file.sha256
            scan_dict["file_size"] = scan.file.file_size
        else:
            scan_dict["filename"] = "Unknown"
            scan_dict["sha256"] = ""
            scan_dict["hash"] = ""
            scan_dict["file_size"] = 0
        scan_dict["created_at"] = scan.scan_date.isoformat() if scan.scan_date else None
        results.append(scan_dict)

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "scans": results,
    }


@router.get("/scan/{scan_id}", response_model=dict)
@router.get("/scans/{scan_id}", response_model=dict)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan result by ID (strictly isolated to owner only)."""
    scan = owned_or_forbidden(
        db.query(Scan).filter(Scan.id == scan_id).first(), current_user
    )

    scan_data = ScanResponse.model_validate(scan)
    res = scan_data.model_dump()
    if scan.file:
        res["file"] = FileResponse.model_validate(scan.file).model_dump()
        res["filename"] = scan.file.original_filename
        res["sha256"] = scan.file.sha256
        res["hash"] = scan.file.sha256
        res["file_size"] = scan.file.file_size
    else:
        res["filename"] = "Unknown"
        res["sha256"] = ""
        res["hash"] = ""
        res["file_size"] = 0
    res["created_at"] = scan.scan_date.isoformat() if scan.scan_date else None
    return res


@router.delete("/scan/{scan_id}")
@router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scan record (strictly isolated to owner only)."""
    scan = owned_or_forbidden(
        db.query(Scan).filter(Scan.id == scan_id).first(), current_user
    )
    db.delete(scan)
    db.commit()

    log = AuditLog(
        user_id=current_user.id,
        action="scan_delete",
        details=f"Deleted scan record #{scan_id}",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"status": "success", "message": f"Scan #{scan_id} deleted successfully."}

