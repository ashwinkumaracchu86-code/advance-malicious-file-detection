from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    identifier: str
    password: str

    @field_validator("identifier")
    @classmethod
    def validate_identifier(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username or email is required")
        if len(v) > 255:
            raise ValueError("Invalid identifier")
        return v


class OTPVerifyRequest(BaseModel):
    temp_token: str
    code: str

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        import re

        v = v.strip()
        if not re.match(r"^\d{6}$", v):
            raise ValueError("OTP must be exactly 6 digits")
        return v


class TokenResponse(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    requires_2fa: bool = False
    message: str | None = None
    temp_token: str | None = None
    expires_in: int | None = None


class RegisterRequest(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    confirm_password: str
    phone_number: str | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        import re

        v = v.strip()
        if not re.match(r"^[a-zA-Z0-9_]{3,50}$", v):
            raise ValueError(
                "Username must be 3-50 characters and contain only letters, numbers, and underscores"
            )
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        import re

        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator("confirm_password")
    @classmethod
    def validate_confirm_password(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Passwords do not match")
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, v: str | None) -> str | None:
        import re

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


class Enable2FARequest(BaseModel):
    phone_number: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str
