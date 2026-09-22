import hashlib


def compute_hashes(data: bytes) -> dict:
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return {"md5": md5, "sha256": sha256}
