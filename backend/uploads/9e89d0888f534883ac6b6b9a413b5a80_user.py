import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator


USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,50}$")
PHONE_REGEX = re.compile(r"^(\+?[1-9]\d{0,2})?[-.\s]?\(?\d{1,5}\)?[-.\s]?\d{1,5}[-.\s]?\d{1,9}$")


def validate_password_strength(value: str) -> str:
    if len(value) < 12:
        raise ValueError("Password must be at least 12 characters long")
    if not re.search(r"[A-Z]", value):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", value):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", value):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
        raise ValueError("Password must contain at least one special character")
    return value


class UserBase(BaseModel):
    email: EmailStr
    full_name: str
    username: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_REGEX.match(v):
            raise ValueError(
                "Username must be 3-50 characters and contain only letters, numbers, and underscores"
            )
        return v


class UserCreate(UserBase):
    password: str
    confirm_password: str
    phone_number: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)

    @field_validator("confirm_password")
    @classmethod
    def validate_confirm_password(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        digits_only = re.sub(r"[^\d]", "", v)
        if len(digits_only) == 10 and digits_only[0] in "6789":
            v = "+91" + digits_only
        if not re.match(r"^\+?[1-9]\d{6,14}$", re.sub(r"[^\d+]", "", v)):
            raise ValueError(
                "Invalid phone number format. Use format like +91XXXXXXXXXX or +1XXXXXXXXXX"
            )
        return v


class UserResponse(BaseModel):
    id: int
    public_id: str
    username: str
    email: str
    full_name: str
    phone_number: str | None = None
    account_status: str
    is_verified: bool
    two_factor_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: str | None = None
    phone_number: str | None = None
