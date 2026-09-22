from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Any
from datetime import datetime


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., max_length=100)
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    role: str = "USER"
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserResponse] = None


class TokenRefresh(BaseModel):
    refresh_token: str


class FileResponse(BaseModel):
    id: int
    original_filename: str
    stored_filename: str
    file_size: int
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    mime_type: Optional[str] = None
    extension: Optional[str] = None
    uploaded_by: Optional[int] = None
    upload_date: Optional[datetime] = None
    is_quarantined: bool = False

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: int
    file_id: int
    user_id: Optional[int] = None
    risk_score: float = 0.0
    classification: str = "unknown"
    entropy: float = 0.0
    suspicious_strings: str = "[]"
    detection_reasons: str = "[]"
    scan_date: Optional[datetime] = None
    vt_detections_count: int = 0
    vt_positives: int = 0
    file: Optional[FileResponse] = None

    class Config:
        from_attributes = True


class QuarantineResponse(BaseModel):
    id: int
    file_id: int
    quarantine_path: str
    original_filename: str
    file_hash: Optional[str] = None
    quarantine_date: Optional[datetime] = None
    status: str = "quarantined"
    reviewed_by: Optional[int] = None

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    details: Optional[str] = None
    timestamp: Optional[datetime] = None
    result: str = "success"

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_scans: int = 0
    total_files: int = 0
    safe_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    quarantined_count: int = 0
    detection_percentage: float = 0.0
    recent_scans: List[Any] = []
    risk_distribution: dict = {}
    file_type_distribution: dict = {}
    daily_scans: List[Any] = []
