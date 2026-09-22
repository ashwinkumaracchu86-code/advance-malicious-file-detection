import magic
import os
from typing import Dict, Optional, Tuple


MIME_TO_EXTENSION = {
    "application/x-executable": ".exe",
    "application/x-dosexec": ".exe",
    "application/x-msdownload": ".exe",
    "application/x-elf": ".elf",
    "application/x-sharedlib": ".so",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/x-rar": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/javascript": ".js",
    "text/javascript": ".js",
    "text/html": ".html",
    "text/plain": ".txt",
    "text/python": ".py",
    "text/x-python": ".py",
    "text/x-shellscript": ".sh",
    "text/x-perl": ".pl",
    "text/x-php": ".php",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "application/x-mach-binary": ".macho",
    "application/x-object": ".o",
    "application/x-archive": ".a",
    "application/x-java-applet": ".class",
    "application/x-java-archive": ".jar",
    "application/vnd.ms-cab-compressed": ".cab",
}

SUSPICIOUS_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-elf",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-java-applet",
    "application/x-java-archive",
}


def detect_mime_type(file_path: str) -> str:
    """Detect the MIME type of a file using python-magic."""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except Exception:
        return "application/octet-stream"


def verify_extension_match(file_path: str, detected_mime: str) -> bool:
    """Verify that the file extension matches the detected MIME type."""
    ext = os.path.splitext(file_path)[1].lower()
    expected_ext = MIME_TO_EXTENSION.get(detected_mime, "")
    if not expected_ext:
        return True
    return ext == expected_ext


def detect_file_signature(file_path: str) -> Optional[str]:
    """Detect file type from magic bytes at the beginning of the file."""
    SIGNATURES = {
        b"\x4d\x5a": "PE executable (Windows)",
        b"\x7f\x45\x4c\x46": "ELF executable (Linux)",
        b"\xca\xfe\xba\xbe": "Mach-O/Fat binary (macOS)",
        b"\x50\x4b\x03\x04": "ZIP archive",
        b"\x52\x61\x72\x21": "RAR archive",
        b"\x37\x7a\xbc\xaf": "7-Zip archive",
        b"\x25\x50\x44\x46": "PDF document",
        b"\x50\x4e\x47": "PNG image",
        b"\xff\xd8\xff": "JPEG image",
        b"\x47\x49\x46\x38": "GIF image",
        b"\x42\x4d": "BMP image",
        b"\x1f\x8b": "GZIP compressed",
        b"\x42\x5a\x68": "BZIP2 compressed",
        b"\xfd\x37\x7a\x58\x5a\x00": "XZ compressed",
        b"\x89\x50\x4e\x47": "PNG image",
        b"\x49\x44\x33": "MP3 audio",
        b"\xff\xfb": "MP3 audio",
        b"\xff\xf3": "MP3 audio",
        b"\x66\x74\x79\x70": "MP4/MOV video",
        b"\x4f\x67\x67\x53": "OGG container",
        b"\x52\x49\x46\x46": "RIFF (AVI/WAV)",
    }

    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for sig, desc in SIGNATURES.items():
            if header[: len(sig)] == sig:
                return desc
    except Exception:
        pass
    return None


def is_suspicious_mime(mime_type: str) -> bool:
    """Check if the MIME type is commonly associated with executables."""
    return mime_type in SUSPICIOUS_MIME_TYPES


def get_file_info(file_path: str) -> Dict[str, any]:
    """Get comprehensive file type information."""
    mime_type = detect_mime_type(file_path)
    extension = os.path.splitext(file_path)[1].lower()
    ext_match = verify_extension_match(file_path, mime_type)
    signature = detect_file_signature(file_path)
    suspicious = is_suspicious_mime(mime_type)

    return {
        "mime_type": mime_type,
        "extension": extension,
        "extension_matches_mime": ext_match,
        "file_signature": signature,
        "is_suspicious_mime": suspicious,
    }
