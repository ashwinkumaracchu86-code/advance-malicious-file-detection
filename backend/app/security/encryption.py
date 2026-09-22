import os
import base64
import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")


def _get_key() -> bytes:
    if not ENCRYPTION_KEY:
        secret = os.getenv("SECRET_KEY", os.getenv("JWT_SECRET", "dev-secret-key-change-in-production"))
        key = hashlib.sha256(secret.encode()).digest()
        logger.warning("ENCRYPTION_KEY not set, deriving from SECRET_KEY. Set ENCRYPTION_KEY in production.")
        return key
    return hashlib.sha256(ENCRYPTION_KEY.encode()).digest()


def encrypt_value(value: str) -> str:
    if not value:
        return ""
    key = _get_key()
    encoded = value.encode("utf-8")
    encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encoded))
    return "enc:" + base64.urlsafe_b64encode(encrypted).decode("utf-8")


def decrypt_value(encrypted_value: str) -> str:
    if not encrypted_value:
        return ""
    if not encrypted_value.startswith("enc:"):
        return encrypted_value
    key = _get_key()
    try:
        encrypted = base64.urlsafe_b64decode(encrypted_value[4:])
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
        return decrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return ""
