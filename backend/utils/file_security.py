import os
import tempfile
import shutil
from werkzeug.utils import secure_filename as _werkzeug_secure


ALLOWED_EXTENSIONS = None
BLOCKED_EXTENSIONS = set()

DANGEROUS_PATTERNS = [
    b"<script",
    b"javascript:",
    b"eval(",
    b"exec(",
    b"subprocess",
    b"os.system",
    b"__import__",
    b"importlib",
]


class FileSecurityError(Exception):
    pass


class EmptyFileError(FileSecurityError):
    pass


class FileTooLargeError(FileSecurityError):
    pass


class BlockedFileError(FileSecurityError):
    pass


class PathTraversalError(FileSecurityError):
    pass


def sanitize_filename(filename: str) -> str:
    safe = _werkzeug_secure(filename)
    if not safe or safe in (".", ".."):
        safe = "unnamed_file"
    return safe


def validate_filename(filename: str) -> None:
    if not filename or not filename.strip():
        raise FileSecurityError("Filename is empty")

    if ".." in filename or "/" in filename or "\\" in filename:
        raise PathTraversalError(f"Path traversal detected in filename: {filename}")

    safe = sanitize_filename(filename)
    if safe != filename:
        raise PathTraversalError(f"Filename contains unsafe characters: {filename}")


def validate_file_size(data: bytes, max_size: int) -> None:
    if len(data) == 0:
        raise EmptyFileError("File is empty")
    if max_size > 0 and len(data) > max_size:
        raise FileTooLargeError(f"File exceeds maximum size of {max_size} bytes")


def validate_extension(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    if BLOCKED_EXTENSIONS and ext in BLOCKED_EXTENSIONS:
        raise BlockedFileError(f"File extension '{ext}' is blocked")

    if ALLOWED_EXTENSIONS and ext not in ALLOWED_EXTENSIONS:
        raise BlockedFileError(f"File extension '{ext}' is not allowed")

    return ext


def scan_for_dangerous_patterns(data: bytes) -> list[str]:
    indicators = []
    lower_data = data.lower()
    for pattern in DANGEROUS_PATTERNS:
        if pattern.lower() in lower_data:
            indicators.append(f"Contains pattern: {pattern.decode('utf-8', errors='replace')}")
    return indicators


def create_secure_tempfile(data: bytes, suffix: str = ".tmp") -> str:
    tmp_dir = tempfile.mkdtemp(prefix="mfds_scan_")
    tmp_path = os.path.join(tmp_dir, f"scan_{suffix}")
    with open(tmp_path, "wb") as f:
        f.write(data)
    return tmp_path


def cleanup_tempfile(path: str) -> None:
    try:
        if os.path.isfile(path):
            os.remove(path)
        parent = os.path.dirname(path)
        if os.path.isdir(parent) and parent.startswith(tempfile.gettempdir()):
            shutil.rmtree(parent, ignore_errors=True)
    except OSError:
        pass
