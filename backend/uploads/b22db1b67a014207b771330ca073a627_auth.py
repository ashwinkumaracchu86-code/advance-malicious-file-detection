from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import decode_token, generate_random_password, generate_random_username
from app.models.user import User
from app.schemas.auth import (
    Enable2FARequest,
    LoginRequest,
    OTPVerifyRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.user import UserResponse
from app.services.auth_service import auth_service
from app.services.session_service import session_service

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["Authentication"])

GENERIC_AUTH_ERROR = "Invalid credentials"


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    return request.headers.get("User-Agent", "unknown")


def set_session_cookies(
    response: JSONResponse,
    session_id: str,
    access_token: str,
    refresh_token: str,
    expires_in: int,
) -> None:
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=expires_in,
        httponly=settings.SESSION_COOKIE_HTTPONLY,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=expires_in,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie("session_id", path="/")
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")


class ResendOTPRequest(BaseModel):
    temp_token: str


class OTPStatusResponse(BaseModel):
    cooldown_seconds: int
    remaining_requests: int
    remaining_attempts: int
    expires_in: int


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_service.register(db, data)
        return user
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login")
async def login(
    request: Request,
    data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        result = await auth_service.login(db, data, ip_address=ip_address, user_agent=user_agent)
        response = JSONResponse(content=result)

        if not result.get("requires_2fa"):
            set_session_cookies(
                response,
                result["session_id"],
                result["access_token"],
                result["refresh_token"],
                result["expires_in"],
            )

        return response
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/verify-otp")
async def verify_otp(
    request: Request,
    data: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        result = await auth_service.verify_otp_and_login(
            db, data.temp_token, data.code, ip_address=ip_address, user_agent=user_agent
        )
        response = JSONResponse(content=result)

        set_session_cookies(
            response,
            result["session_id"],
            result["access_token"],
            result["refresh_token"],
            result["expires_in"],
        )

        return response
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/resend-otp")
async def resend_otp(
    request: Request,
    data: ResendOTPRequest,
    db: AsyncSession = Depends(get_db),
):
    ip_address = get_client_ip(request)
    user_agent = get_user_agent(request)

    try:
        result = await auth_service.resend_otp(
            db, data.temp_token, ip_address=ip_address, user_agent=user_agent
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/otp-status", response_model=OTPStatusResponse)
async def get_otp_status(
    temp_token: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        result = await auth_service.get_otp_status(db, temp_token)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active session found",
        )

    try:
        success = await auth_service.logout(db, session_id)
        if success:
            clear_session_cookies(response)
            return {"message": "Logged out successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session already invalid",
            )
    except HTTPException:
        raise
    except Exception:
        clear_session_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed",
        )


@router.post("/refresh")
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    session_id = request.cookies.get("session_id")
    refresh_token = request.cookies.get("refresh_token")

    if not session_id or not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No valid session found",
        )

    try:
        result = await auth_service.refresh_session(
            db, session_id, refresh_token, get_client_ip(request)
        )
        if result:
            response = JSONResponse(content=result)
            set_session_cookies(
                response,
                session_id,
                result["access_token"],
                result["refresh_token"],
                result["expires_in"],
            )
            return response
        else:
            response = JSONResponse(content={"detail": "Session expired or invalid"}, status_code=status.HTTP_401_UNAUTHORIZED)
            clear_session_cookies(response)
            return response
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed",
        )


class Confirm2FARequest(BaseModel):
    temp_token: str
    code: str


async def _get_user_from_session(
    request: Request,
    db: AsyncSession,
) -> User | None:
    session_id = request.cookies.get("session_id")
    access_token = request.cookies.get("access_token")
    if not session_id or not access_token:
        return None
    payload = decode_token(access_token)
    if not payload:
        return None
    try:
        user_id = int(payload["sub"])
    except (KeyError, ValueError):
        return None
    valid, _ = await session_service.validate_session(db, session_id, access_token)
    if not valid:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


@router.post("/enable-2fa")
async def enable_2fa(
    request: Request,
    data: Enable2FARequest,
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user_from_session(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    temp_token = await auth_service.enable_2fa(db, user.id, data.phone_number)
    if not temp_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to enable 2FA")
    return {"message": "OTP sent to your phone for verification", "temp_token": temp_token}


@router.post("/confirm-2fa")
async def confirm_2fa(
    request: Request,
    data: Confirm2FARequest,
    db: AsyncSession = Depends(get_db),
):
    user = await _get_user_from_session(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    success = await auth_service.confirm_enable_2fa(
        db, user.id, data.temp_token, data.code
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
    return {"message": "2FA enabled successfully"}


@router.get("/generate-credentials")
async def generate_credentials():
    return {
        "username": generate_random_username(),
        "password": generate_random_password(),
    }
