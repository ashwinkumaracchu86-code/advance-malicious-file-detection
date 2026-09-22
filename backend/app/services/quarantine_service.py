import os
import shutil
import uuid
import logging
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..models.models import QuarantineItem, File

logger = logging.getLogger(__name__)

QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "quarantine"))


def ensure_quarantine_dir() -> None:
    """Create quarantine directory if it does not exist."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)


def quarantine_file(
    file_path: str,
    original_filename: str,
    file_hash: str,
    db: Session,
    user_id: Optional[int] = None,
) -> Optional[QuarantineItem]:
    """Move a file to quarantine and create a database record."""
    ensure_quarantine_dir()

    if not os.path.isfile(file_path):
        logger.error(f"File not found for quarantine: {file_path}")
        return None

    try:
        quarantine_name = f"{uuid.uuid4().hex}_{original_filename}"
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        shutil.move(file_path, quarantine_path)

        item = QuarantineItem(
            file_id=None,
            quarantine_path=quarantine_path,
            original_filename=original_filename,
            file_hash=file_hash,
            status="quarantined",
            reviewed_by=user_id,
        )

        file_record = db.query(File).filter(File.file_path == file_path).first()
        if file_record:
            item.file_id = file_record.id
            file_record.is_quarantined = True

        db.add(item)
        db.commit()
        db.refresh(item)

        logger.info(f"File quarantined: {original_filename} -> {quarantine_path}")
        return item

    except Exception as e:
        db.rollback()
        logger.error(f"Quarantine failed: {e}")
        return None


def list_quarantined(db: Session) -> List[QuarantineItem]:
    """List all quarantined items."""
    return db.query(QuarantineItem).filter(
        QuarantineItem.status == "quarantined"
    ).order_by(QuarantineItem.quarantine_date.desc()).all()


def get_quarantine_item(quarantine_id: int, db: Session) -> Optional[QuarantineItem]:
    """Get a specific quarantine item by ID."""
    return db.query(QuarantineItem).filter(QuarantineItem.id == quarantine_id).first()


def restore_file(quarantine_id: int, db: Session) -> bool:
    """Restore a quarantined file to its original location."""
    item = get_quarantine_item(quarantine_id, db)
    if not item:
        logger.error(f"Quarantine item not found: {quarantine_id}")
        return False

    if not os.path.isfile(item.quarantine_path):
        logger.error(f"Quarantined file not found on disk: {item.quarantine_path}")
        item.status = "missing"
        db.commit()
        return False

    try:
        if item.file_id:
            file_record = db.query(File).filter(File.id == item.file_id).first()
            if file_record:
                restore_dir = os.path.dirname(file_record.file_path)
                os.makedirs(restore_dir, exist_ok=True)
                shutil.move(item.quarantine_path, file_record.file_path)
                file_record.is_quarantined = False
                item.status = "restored"
                db.commit()
                logger.info(f"File restored: {item.original_filename}")
                return True

        restore_dir = os.path.join(os.path.dirname(QUARANTINE_DIR), "restored")
        os.makedirs(restore_dir, exist_ok=True)
        restore_path = os.path.join(restore_dir, item.original_filename)
        shutil.move(item.quarantine_path, restore_path)
        item.status = "restored"
        db.commit()
        logger.info(f"File restored to: {restore_path}")
        return True

    except Exception as e:
        db.rollback()
        logger.error(f"Restore failed: {e}")
        return False


def delete_file(quarantine_id: int, db: Session) -> bool:
    """Permanently delete a quarantined file."""
    item = get_quarantine_item(quarantine_id, db)
    if not item:
        logger.error(f"Quarantine item not found: {quarantine_id}")
        return False

    try:
        if os.path.isfile(item.quarantine_path):
            os.remove(item.quarantine_path)

        if item.file_id:
            file_record = db.query(File).filter(File.id == item.file_id).first()
            if file_record and os.path.isfile(file_record.file_path):
                os.remove(file_record.file_path)

        item.status = "deleted"
        db.commit()
        logger.info(f"Quarantined file permanently deleted: {item.original_filename}")
        return True

    except Exception as e:
        db.rollback()
        logger.error(f"Delete failed: {e}")
        return False
