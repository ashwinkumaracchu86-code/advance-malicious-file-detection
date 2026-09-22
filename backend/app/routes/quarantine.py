from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, File as FileModel, QuarantineItem, AuditLog
from ..schemas.schemas import QuarantineResponse
from ..security.auth import get_current_user
from ..services import quarantine_service

router = APIRouter(prefix="/quarantine", tags=["Quarantine"])


@router.post("/{file_id}", response_model=QuarantineResponse, status_code=status.HTTP_201_CREATED)
def quarantine_file(
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Quarantine a file by moving it to the quarantine directory."""
    file_record = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    if file_record.is_quarantined:
        raise HTTPException(status_code=400, detail="File is already quarantined")

    item = quarantine_service.quarantine_file(
        file_path=file_record.file_path,
        original_filename=file_record.original_filename,
        file_hash=file_record.sha256 or "",
        db=db,
        user_id=current_user.id,
    )

    if not item:
        raise HTTPException(status_code=500, detail="Failed to quarantine file")

    log = AuditLog(
        user_id=current_user.id,
        action="file_quarantine",
        details=f"Quarantined file: {file_record.original_filename} (ID: {file_id})",
        result="success",
    )
    db.add(log)
    db.commit()

    return QuarantineResponse.model_validate(item)


@router.get("", response_model=List[QuarantineResponse])
def list_quarantined(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all quarantined items."""
    items = quarantine_service.list_quarantined(db)
    return [QuarantineResponse.model_validate(item) for item in items]


@router.post("/{item_id}/restore")
def restore_file(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Restore a quarantined file to its original location."""
    item = quarantine_service.get_quarantine_item(item_id, db)
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found")

    success = quarantine_service.restore_file(item_id, db)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to restore file")

    log = AuditLog(
        user_id=current_user.id,
        action="file_restore",
        details=f"Restored file: {item.original_filename} (Quarantine ID: {item_id})",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"message": f"File {item.original_filename} restored successfully"}


@router.delete("/{item_id}")
def delete_quarantined_file(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Permanently delete a quarantined file (admin only)."""
    item = quarantine_service.get_quarantine_item(item_id, db)
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found")

    success = quarantine_service.delete_file(item_id, db)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete file")

    log = AuditLog(
        user_id=current_user.id,
        action="file_delete",
        details=f"Permanently deleted quarantined file: {item.original_filename} (Quarantine ID: {item_id})",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"message": f"File {item.original_filename} permanently deleted"}
