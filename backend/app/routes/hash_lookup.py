import re
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, Scan, File as FileModel, AuditLog
from ..security.auth import get_current_user
from ..services.virustotal import query_hash as vt_query_hash

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hash-lookup", tags=["Hash Lookup"])

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def detect_hash_type(hash_str: str) -> Optional[str]:
    for htype, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_str):
            return htype
    return None


class HashLookupRequest(BaseModel):
    hashes: List[str] = Field(..., min_length=1, max_length=50)


class HashLookupResult(BaseModel):
    hash: str
    hash_type: str
    found_locally: bool
    local_scan: Optional[dict] = None
    vt_result: Optional[dict] = None
    threat_level: str = "unknown"


def assess_threat_level(vt_result: Optional[dict], local_scan: Optional[dict]) -> str:
    if vt_result and vt_result.get("found"):
        positives = vt_result.get("positives", 0)
        if positives >= 10:
            return "critical"
        elif positives >= 5:
            return "high"
        elif positives >= 2:
            return "medium"
        elif positives >= 1:
            return "low"
        return "clean"

    if local_scan:
        classification = local_scan.get("classification", "unknown")
        if classification == "malicious":
            return "high"
        elif classification == "suspicious":
            return "medium"
        elif classification == "safe":
            return "clean"

    return "unknown"


@router.post("/lookup")
def lookup_hashes(
    request: HashLookupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Look up multiple file hashes against local database and VirusTotal."""
    results = []

    for hash_str in request.hashes:
        hash_str = hash_str.strip().lower()
        hash_type = detect_hash_type(hash_str)

        if not hash_type:
            results.append({
                "hash": hash_str,
                "hash_type": "unknown",
                "found_locally": False,
                "local_scan": None,
                "vt_result": None,
                "threat_level": "invalid",
                "error": "Invalid hash format (expected MD5, SHA-1, or SHA-256)",
            })
            continue

        local_scan = None
        found_locally = False

        file_record = db.query(FileModel).filter(
            (FileModel.md5 == hash_str) |
            (FileModel.sha1 == hash_str) |
            (FileModel.sha256 == hash_str)
        ).first()

        if file_record:
            found_locally = True
            scan = db.query(Scan).filter(Scan.file_id == file_record.id).order_by(Scan.scan_date.desc()).first()
            if scan:
                local_scan = {
                    "scan_id": scan.id,
                    "risk_score": scan.risk_score,
                    "classification": scan.classification,
                    "scan_date": str(scan.scan_date),
                    "filename": file_record.original_filename,
                    "detection_reasons": scan.detection_reasons,
                }

        vt_result = None
        try:
            vt_result = vt_query_hash(hash_str)
        except Exception as e:
            logger.error(f"VT query failed for {hash_str}: {e}")

        threat_level = assess_threat_level(vt_result, local_scan)

        results.append({
            "hash": hash_str,
            "hash_type": hash_type,
            "found_locally": found_locally,
            "local_scan": local_scan,
            "vt_result": vt_result,
            "threat_level": threat_level,
        })

    log = AuditLog(
        user_id=current_user.id,
        action="hash_lookup",
        details=f"Looked up {len(request.hashes)} hash(es)",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"results": results, "total": len(results)}


@router.get("/recent")
def get_recent_lookups(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get recent hash lookup audit logs."""
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.action == "hash_lookup")
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return {
        "lookups": [
            {
                "id": log.id,
                "details": log.details,
                "timestamp": str(log.timestamp),
                "result": log.result,
            }
            for log in logs
        ]
    }
