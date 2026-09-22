import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.file import ProtectedFile

logger = logging.getLogger(__name__)

SAMPLE_FILES = [
    {
        "filename": "security_policy.txt",
        "description": "Comprehensive security policy document covering authentication, access control, and data protection requirements.",
        "mime_type": "text/plain",
    },
    {
        "filename": "network_architecture.txt",
        "description": "Network security architecture document with firewall rules, IDS configuration, and VPN setup details.",
        "mime_type": "text/plain",
    },
    {
        "filename": "api_security_config.json",
        "description": "API security configuration including CSP headers, CORS settings, and rate limiting policies.",
        "mime_type": "application/json",
    },
    {
        "filename": "incident_response_plan.txt",
        "description": "Incident response plan with severity levels, response procedures, and contact information.",
        "mime_type": "text/plain",
    },
]


def calculate_sha256(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


async def initialize_sample_files():
    sample_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample_files")
    sample_dir = os.path.abspath(sample_dir)

    async with AsyncSessionLocal() as db:
        for file_info in SAMPLE_FILES:
            file_path = os.path.join(sample_dir, file_info["filename"])

            if not os.path.exists(file_path):
                logger.warning("Sample file not found: %s", file_path)
                continue

            existing = await db.execute(
                select(ProtectedFile).where(
                    ProtectedFile.original_filename == file_info["filename"]
                )
            )
            if existing.scalar_one_or_none():
                logger.info("Sample file already exists: %s", file_info["filename"])
                continue

            file_size = os.path.getsize(file_path)
            checksum = calculate_sha256(file_path)

            protected_file = ProtectedFile(
                file_id=secrets.token_urlsafe(16),
                filename=file_info["filename"],
                original_filename=file_info["filename"],
                description=file_info["description"],
                file_size=file_size,
                mime_type=file_info["mime_type"],
                storage_path=file_path,
                checksum_sha256=checksum,
                is_active=True,
                requires_2fa=True,
            )
            db.add(protected_file)
            logger.info("Added sample file: %s", file_info["filename"])

        await db.commit()
        logger.info("Sample files initialization complete")


if __name__ == "__main__":
    import asyncio
    asyncio.run(initialize_sample_files())
