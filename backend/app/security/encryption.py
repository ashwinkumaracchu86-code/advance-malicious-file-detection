import os
import base64
import hashlib
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")


def _get_raw_key() -> bytes:
    if not ENCRYPTION_KEY:
        secret = os.getenv("SECRET_KEY", os.getenv("JWT_SECRET", "dev-secret-key-change-in-production"))
        return hashlib.sha256(secret.encode()).digest()
    return hashlib.sha256(ENCRYPTION_KEY.encode()).digest()


def _get_fernet() -> Fernet:
    """Return a Fernet cipher instance using the derived 32-byte urlsafe key."""
    key = _get_raw_key()
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive string (e.g. email App Password) using strong Fernet encryption."""
    if not value:
        return ""
    try:
        f = _get_fernet()
        token = f.encrypt(value.encode("utf-8")).decode("utf-8")
        return "fnt:" + token
    except Exception as e:
        logger.error(f"Fernet encryption failed: {e}")
        # Fallback to enc: prefix
        key = _get_raw_key()
        encoded = value.encode("utf-8")
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encoded))
        return "enc:" + base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a sensitive string, supporting Fernet ('fnt:'), legacy ('enc:'), and unencrypted."""
    if not encrypted_value:
        return ""
    if encrypted_value.startswith("fnt:"):
        try:
            f = _get_fernet()
            token = encrypted_value[4:].encode("utf-8")
            return f.decrypt(token).decode("utf-8")
        except (InvalidToken, Exception) as e:
            logger.error(f"Fernet decryption failed: {e}")
            return ""
    elif encrypted_value.startswith("enc:"):
        key = _get_raw_key()
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_value[4:])
            decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
            return decrypted.decode("utf-8")
        except Exception as e:
            logger.error(f"Legacy decryption failed: {e}")
            return ""
    return encrypted_value

