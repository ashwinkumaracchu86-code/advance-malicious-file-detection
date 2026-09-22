from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..database import get_db
from ..models.models import User, AuditLog
from ..schemas.schemas import AuditLogResponse
from ..security.auth import get_current_user

router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@router.get("", response_model=dict)
def list_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    search: Optional[str] = None,
    user_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List audit logs with pagination and filtering."""
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action)
    if search:
        query = query.filter(AuditLog.action.contains(search) | AuditLog.details.contains(search))
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    total = query.count()
    logs = query.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [AuditLogResponse.model_validate(log).model_dump() for log in logs],
    }
