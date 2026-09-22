MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": {"type": "image", "subtype": "png", "mime": "image/png"},
    b"\xff\xd8\xff": {"type": "image", "subtype": "jpeg", "mime": "image/jpeg"},
    b"GIF87a": {"type": "image", "subtype": "gif", "mime": "image/gif"},
    b"GIF89a": {"type": "image", "subtype": "gif", "mime": "image/gif"},
    b"RIFF": {"type": "image", "subtype": "webp", "mime": "image/webp"},
    b"\x00\x00\x00": {"type": "image", "subtype": "mp4", "mime": "video/mp4"},
    b"\x1a\x45\xdf\xa3": {"type": "video", "subtype": "mkv", "mime": "video/x-matroska"},
    b"\x52\x49\x46\x46": {"type": "audio", "subtype": "wav", "mime": "audio/wav"},
    b"ID3": {"type": "audio", "subtype": "mp3", "mime": "audio/mpeg"},
    b"\xff\xfb": {"type": "audio", "subtype": "mp3", "mime": "audio/mpeg"},
    b"\xff\xf3": {"type": "audio", "subtype": "mp3", "mime": "audio/mpeg"},
    b"\xff\xf2": {"type": "audio", "subtype": "mp3", "mime": "audio/mpeg"},
    b"OggS": {"type": "audio", "subtype": "ogg", "mime": "audio/ogg"},
    b"%PDF": {"type": "document", "subtype": "pdf", "mime": "application/pdf"},
    b"PK\x03\x04": {"type": "archive", "subtype": "zip", "mime": "application/zip"},
    b"PK\x05\x06": {"type": "archive", "subtype": "zip", "mime": "application/zip"},
    b"\x1f\x8b": {"type": "archive", "subtype": "gzip", "mime": "application/gzip"},
    b"BZh": {"type": "archive", "subtype": "bzip2", "mime": "application/x-bzip2"},
    b"\xfd7zXZ\x00": {"type": "archive", "subtype": "xz", "mime": "application/x-xz"},
    b"7z\xbc\xaf\x27\x1c": {"type": "archive", "subtype": "7z", "mime": "application/x-7z-compressed"},
    b"Rar!\x1a\x07\x01\x00": {"type": "archive", "subtype": "rar", "mime": "application/vnd.rar"},
    b"\x50\x4b\x03\x04": {"type": "archive", "subtype": "zip", "mime": "application/zip"},
    b"\xd0\xcf\x11\xe0": {"type": "document", "subtype": "ole", "mime": "application/msword"},
    b"\xef\xbb\xbf": {"type": "text", "subtype": "utf8_bom", "mime": "text/plain"},
    b"\xff\xfe": {"type": "text", "subtype": "utf16_le_bom", "mime": "text/plain"},
    b"\xfe\xff": {"type": "text", "subtype": "utf16_be_bom", "mime": "text/plain"},
}

TEXT_MIME_EXTENSIONS = {
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".xml": "application/xml",
    ".csv": "text/csv",
    ".md": "text/markdown",
    ".py": "text/x-python",
    ".java": "text/x-java-source",
    ".c": "text/x-c",
    ".cpp": "text/x-c++",
    ".h": "text/x-c",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".sh": "text/x-shellscript",
    ".bat": "text/x-bat",
    ".ps1": "text/plain",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".toml": "text/plain",
    ".ini": "text/plain",
    ".cfg": "text/plain",
    ".log": "text/plain",
    ".sql": "text/plain",
}


def detect_type_from_bytes(data: bytes) -> dict:
    if not data:
        return {"type": "unknown", "subtype": "empty", "mime": "application/octet-stream"}

    for magic, info in MAGIC_BYTES.items():
        if data[: len(magic)] == magic:
            return dict(info)

    if _looks_like_text(data):
        return {"type": "text", "subtype": "plain", "mime": "text/plain"}

    return {"type": "unknown", "subtype": "unknown", "mime": "application/octet-stream"}


def detect_type_from_extension(extension: str) -> str:
    ext = extension.lower().lstrip(".")
    return TEXT_MIME_EXTENSIONS.get(f".{ext}", "application/octet-stream")


def _looks_like_text(data: bytes, sample_size: int = 8192) -> bool:
    sample = data[:sample_size]
    if not sample:
        return False

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False

    non_text = 0
    for byte in sample:
        if byte < 9 or (byte > 13 and byte < 32) or byte == 127:
            non_text += 1

    return (non_text / len(sample)) < 0.1
