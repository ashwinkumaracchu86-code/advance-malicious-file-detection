import os
import re
import uuid
from typing import Optional


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename by removing or replacing dangerous characters."""
    filename = os.path.basename(filename)
    filename = filename.strip(". ")
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", filename)
    filename = re.sub(r"\.\.", "_", filename)
    if not filename:
        filename = "unnamed_file"
    return filename


def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human-readable file size."""
    if size_bytes < 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)

    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024.0

    return f"{size:.1f} PB"


def generate_unique_id() -> str:
    """Generate a UUID4 unique identifier."""
    return str(uuid.uuid4())


def safe_path_join(base: str, user_input: str) -> Optional[str]:
    """Safely join a base path with user input, preventing path traversal.

    Returns None if the resulting path is outside the base directory.
    """
    base = os.path.realpath(base)
    user_input = sanitize_filename(user_input)
    joined = os.path.realpath(os.path.join(base, user_input))

    if not joined.startswith(base + os.sep) and joined != base:
        return None

    return joined


def get_file_extension(filename: str) -> str:
    """Get the file extension in lowercase."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def is_safe_extension(extension: str) -> bool:
    """Check if a file extension is generally safe."""
    safe_exts = {
        ".txt", ".csv", ".json", ".xml", ".html", ".css", ".js",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
        ".mp3", ".mp4", ".wav", ".flac", ".ogg",
    }
    return extension.lower() in safe_exts
