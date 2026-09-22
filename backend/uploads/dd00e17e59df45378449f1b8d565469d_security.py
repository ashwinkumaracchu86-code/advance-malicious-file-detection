import hashlib
import hmac
import secrets
import string
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def timing_safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except JWTError:
        return None


def generate_random_username(length: int = 12) -> str:
    prefix = secrets.choice(["user", "account", "member", "secure"])
    random_part = secrets.token_hex(length // 2)
    return f"{prefix}_{random_part}"


def generate_random_password(length: int = 20) -> str:
    if length < 16:
        length = 16

    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation),
    ]

    all_chars = string.ascii_letters + string.digits + string.punctuation
    remaining_length = length - len(password_chars)
    password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))

    password_list = list(password_chars)
    secrets.SystemRandom().shuffle(password_list)

    return "".join(password_list)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_secure_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)
