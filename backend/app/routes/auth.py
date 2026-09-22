from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models.models import User, AuditLog
from ..schemas.schemas import UserCreate, UserLogin, LoginRequest, Token, TokenRefresh, UserResponse
from ..security.auth import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
    verify_token,
    get_current_user,
    validate_password_strength,
    ADMIN_ROLE,
    USER_ROLE,
)
from ..security.middleware import login_tracker

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=Token)
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    client_ip = _get_client_ip(req)

    if login_tracker.is_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )

    user = db.query(User).filter(User.username == request.username).first()
    if not user or not verify_password(request.password, user.hashed_password):
        login_tracker.record_failed_attempt(client_ip)
        remaining = login_tracker.get_remaining_attempts(client_ip)

        log = AuditLog(
            user_id=user.id if user else None,
            action="login_failed",
            details=f"Failed login attempt for username: {request.username} from IP: {client_ip}",
            result="failure",
        )
        db.add(log)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. {remaining} attempts remaining before lockout.",
        )

    login_tracker.clear_attempts(client_ip)

    access_token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
    user_data = UserResponse.model_validate(user)

    log = AuditLog(
        user_id=user.id,
        action="login_success",
        details=f"User {user.username} logged in from IP: {client_ip}",
        result="success",
    )
    db.add(log)
    db.commit()

    return Token(access_token=access_token, refresh_token=refresh_token, user=user_data)


@router.post("/refresh", response_model=Token)
def refresh_token(token_data: TokenRefresh, db: Session = Depends(get_db)):
    """Refresh an expired access token using a refresh token."""
    payload = verify_token(token_data.refresh_token, token_type="refresh")
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload",
        )

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    access_token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
    new_refresh_token = create_refresh_token(data={"sub": str(user.id), "username": user.username, "role": user.role})
    user_data = UserResponse.model_validate(user)

    return Token(access_token=access_token, refresh_token=new_refresh_token, user=user_data)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with password strength validation. Always creates USER role."""
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
        role=USER_ROLE,
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return UserResponse.model_validate(current_user)
