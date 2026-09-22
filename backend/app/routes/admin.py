from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from ..database import get_db
from ..models.models import User, AuditLog
from ..schemas.schemas import UserResponse
from ..security.auth import get_current_user, require_admin, get_password_hash, validate_password_strength, ADMIN_ROLE, USER_ROLE

router = APIRouter(prefix="/admin", tags=["Admin User Management"])


class AdminUserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=100)
    password: str = Field(..., min_length=6)
    role: str = Field(default=USER_ROLE, pattern="^(ADMIN|USER)$")


class AdminUserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = Field(None, pattern="^(ADMIN|USER)$")
    is_active: Optional[bool] = None


@router.get("/users", response_model=dict)
def list_users(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all users (admin only)."""
    total = db.query(User).count()
    users = db.query(User).offset(skip).limit(limit).all()
    return {
        "total": total,
        "users": [UserResponse.model_validate(u).model_dump() for u in users],
    }


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user_data: AdminUserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new user (admin only). Admin can create both ADMIN and USER roles."""
    password_errors = validate_password_strength(user_data.password)
    if password_errors:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet security requirements", "errors": password_errors},
        )

    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        role=user_data.role,
        is_admin=(user_data.role == ADMIN_ROLE),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log = AuditLog(
        user_id=current_user.id,
        action="admin_user_created",
        details=f"Created user: {user.username} with role: {user.role}",
        result="success",
    )
    db.add(log)
    db.commit()

    return UserResponse.model_validate(user)


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: AdminUserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a user (admin only). Can change role."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot modify your own account via this endpoint")

    if user_data.email is not None:
        existing = db.query(User).filter(User.email == user_data.email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already in use")
        user.email = user_data.email

    if user_data.role is not None:
        user.role = user_data.role
        user.is_admin = (user_data.role == ADMIN_ROLE)

    db.commit()
    db.refresh(user)

    log = AuditLog(
        user_id=current_user.id,
        action="admin_user_updated",
        details=f"Updated user: {user.username}, role: {user.role}",
        result="success",
    )
    db.add(log)
    db.commit()

    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a user (admin only). Cannot delete yourself."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    username = user.username
    db.delete(user)
    db.commit()

    log = AuditLog(
        user_id=current_user.id,
        action="admin_user_deleted",
        details=f"Deleted user: {username}",
        result="success",
    )
    db.add(log)
    db.commit()

    return {"message": f"User {username} deleted successfully"}
