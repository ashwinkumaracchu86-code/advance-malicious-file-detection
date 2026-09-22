import hashlib
import os
from typing import Dict


def calculate_hashes(file_path: str) -> Dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 hashes for a file, reading in chunks."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    chunk_size = 8192

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
