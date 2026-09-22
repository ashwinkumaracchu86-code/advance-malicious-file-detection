import os
import json
import uuid
import shutil
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, File as FileModel, Scan, AuditLog
from ..schemas.schemas import FileResponse, ScanResponse
from ..security.auth import get_current_user
from ..security.middleware import MAX_UPLOAD_SIZE_BYTES, BLOCKED_EXTENSIONS
from ..scanner.file_analyzer import analyze_file
from ..scanner.hash_calculator import calculate_hashes
from ..scanner.mime_detector import detect_mime_type
from ..services.virustotal import query_hash
from ..services.alert_service import create_alert
from ..utils.helpers import sanitize_filename

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["Files"])

UPLOADS_DIR = os.getenv("UPLOADS_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "uploads"))


def _validate_upload_file(upload_file: UploadFile) -> str:
    ext = os.path.splitext(upload_file.filename or "")[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '{ext}' is not allowed for security reasons.",
        )
    return ext


@router.post("/upload", response_model=dict, status_code=status.HTTP_201_CREATED)
async def upload_files(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Upload one or more files and automatically scan them."""
    os.makedirs(UPLOADS_DIR, exist_ok=True)

    results = []

    for upload_file in files:
        try:
            _validate_upload_file(upload_file)

            safe_name = sanitize_filename(upload_file.filename or "unnamed")
            unique_name = f"{uuid.uuid4().hex}_{safe_name}"
            file_path = os.path.join(UPLOADS_DIR, unique_name)

            content = await upload_file.read()

            if len(content) > MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File '{safe_name}' exceeds maximum size of {MAX_UPLOAD_SIZE_BYTES // (1024*1024)}MB.",
                )

            if len(content) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"File '{safe_name}' is empty.",
                )

            with open(file_path, "wb") as f:
                f.write(content)

            file_size = len(content)
            hashes = calculate_hashes(file_path)
            mime_type = detect_mime_type(file_path)
            ext = os.path.splitext(safe_name)[1].lower()

            file_record = FileModel(
                original_filename=safe_name,
                stored_filename=unique_name,
                file_path=file_path,
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
            analysis = analyze_file(file_path, vt_results)
            analysis["original_filename"] = safe_name

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
                action="file_upload",
                details=f"Uploaded {safe_name} ({file_size} bytes). Classification: {analysis.get('classification', 'unknown')}",
                result="success",
            )
            db.add(log)
            db.commit()

            classification = analysis.get("classification", "unknown")
            if classification in ("malicious", "suspicious"):
                create_alert(analysis, db, current_user.id)

            results.append({
                "file": FileResponse.model_validate(file_record).model_dump(),
                "scan": {
                    "id": scan.id,
                    "risk_score": scan.risk_score,
                    "classification": scan.classification,
                    "entropy": scan.entropy,
                    "detection_reasons": analysis.get("detection_reasons", []),
                },
            })

        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            db.rollback()
            results.append({
                "filename": upload_file.filename,
                "error": str(e),
            })

    return {"uploaded": len(results), "results": results}


@router.get("", response_model=List[FileResponse])
def list_files(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List uploaded files with pagination."""
    files = db.query(FileModel).order_by(FileModel.upload_date.desc()).offset(skip).limit(limit).all()
    return [FileResponse.model_validate(f) for f in files]


@router.get("/{file_id}", response_model=FileResponse)
def get_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get file details by ID."""
    file_record = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse.model_validate(file_record)
