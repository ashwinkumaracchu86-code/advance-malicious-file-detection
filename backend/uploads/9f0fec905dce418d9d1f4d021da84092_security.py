from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User
from app.services.security_audit import security_audit
from app.services.session_service import session_service

router = APIRouter(prefix="/security", tags=["Security"])


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    session_id = request.cookies.get("session_id")
    access_token = request.cookies.get("access_token")

    if not session_id or not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user_id = int(payload["sub"])

    valid, session = await session_service.validate_session(
        db, session_id, access_token
    )

    if not valid or not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    return user


class ActivityResponse(BaseModel):
    id: int
    event_type: str
    event_description: str
    severity: str
    ip_address: str | None
    user_agent: str | None
    resource_type: str | None
    resource_id: str | None
    created_at: datetime


class ActivityListResponse(BaseModel):
    events: list[ActivityResponse]
    total: int
    limit: int
    offset: int


class SecurityStatsResponse(BaseModel):
    total_events: int
    recent_events_24h: int
    failed_logins_7d: int
    successful_logins_7d: int
    warnings_7d: int


EVENT_TYPES = [
    "user_registration",
    "login_success",
    "login_failure",
    "otp_generated",
    "otp_success",
    "otp_failure",
    "otp_resend",
    "account_lockout",
    "rate_limit_hit",
    "file_download_success",
    "file_download_failure",
    "logout",
    "session_anomaly",
    "password_change",
    "2fa_enabled",
    "2fa_disabled",
]

SEVERITY_LEVELS = ["info", "warning", "error", "critical"]


@router.get("/activity", response_model=ActivityListResponse)
async def get_my_activity(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
):
    if event_type and event_type not in EVENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event type. Must be one of: {', '.join(EVENT_TYPES)}",
        )

    events = await security_audit.get_user_activity(
        db, user.id, limit=limit, offset=offset
    )

    if event_type:
        events = [e for e in events if e.event_type == event_type]

    total = await security_audit.get_activity_count(db, user_id=user.id)

    return ActivityListResponse(
        events=[
            ActivityResponse(
                id=e.id,
                event_type=e.event_type,
                event_description=e.event_description,
                severity=e.severity,
                ip_address=e.ip_address,
                user_agent=e.user_agent,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                created_at=e.created_at,
            )
            for e in events
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/activity/all", response_model=ActivityListResponse)
async def get_all_activity(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    if event_type and event_type not in EVENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event type. Must be one of: {', '.join(EVENT_TYPES)}",
        )

    if severity and severity not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity. Must be one of: {', '.join(SEVERITY_LEVELS)}",
        )

    events = await security_audit.get_all_activity(
        db, limit=limit, offset=offset,
        event_type=event_type, severity=severity,
    )

    total = await security_audit.get_activity_count(
        db, event_type=event_type,
    )

    return ActivityListResponse(
        events=[
            ActivityResponse(
                id=e.id,
                event_type=e.event_type,
                event_description=e.event_description,
                severity=e.severity,
                ip_address=e.ip_address,
                user_agent=e.user_agent,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                created_at=e.created_at,
            )
            for e in events
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/stats", response_model=SecurityStatsResponse)
async def get_security_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    stats = await security_audit.get_security_stats(db, user_id=user.id)
    return SecurityStatsResponse(**stats)


@router.get("/event-types")
async def get_event_types():
    return {"event_types": EVENT_TYPES, "severity_levels": SEVERITY_LEVELS}
