import os
from datetime import datetime, timezone


def extract_metadata(file_path: str, original_filename: str) -> dict:
    metadata = {
        "original_filename": original_filename,
        "extension": _get_extension(original_filename),
        "basename": _get_basename(original_filename),
    }

    try:
        stat = os.stat(file_path)
        metadata["file_size"] = stat.st_size
        metadata["created_at"] = _timestamp_to_iso(stat.st_ctime)
        metadata["modified_at"] = _timestamp_to_iso(stat.st_mtime)
        metadata["accessed_at"] = _timestamp_to_iso(stat.st_atime)
    except OSError:
        metadata["file_size"] = 0
        metadata["created_at"] = None
        metadata["modified_at"] = None
        metadata["accessed_at"] = None

    return metadata


def _get_extension(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _get_basename(filename: str) -> str:
    return os.path.splitext(os.path.basename(filename))[0]


def _timestamp_to_iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OSError, ValueError, OverflowError):
        return None
