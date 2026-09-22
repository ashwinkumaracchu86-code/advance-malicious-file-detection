from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class RuleResult:
    name: str
    description: str
    severity: str
    points: int
    detected: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "points": self.points,
            "detected": self.detected,
        }


EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".pif",
    ".jar", ".elf", ".app", ".dmg", ".pkg", ".deb", ".rpm",
}

SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
    ".ws", ".wsh", ".wsf", ".sh", ".bash", ".csh", ".ksh",
    ".rb", ".py", ".pl", ".php", ".asp", ".aspx", ".jsp",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tar.gz", ".tgz",
}

SUSPICIOUS_FILENAME_PATTERNS = [
    (r"(?i)invoice", "Filename contains 'invoice'"),
    (r"(?i)payroll", "Filename contains 'payroll'"),
    (r"(?i)confidential", "Filename contains 'confidential'"),
    (r"(?i)secret", "Filename contains 'secret'"),
    (r"(?i)urgent", "Filename contains 'urgent'"),
    (r"(?i)important", "Filename contains 'important'"),
    (r"(?i)do.not.open", "Filename contains 'do not open'"),
    (r"(?i)click.me", "Filename contains 'click me'"),
    (r"(?i)you.won", "Filename contains 'you won'"),
    (r"(?i)free.download", "Filename contains 'free download'"),
    (r"(?i)admin", "Filename contains 'admin'"),
    (r"(?i)password", "Filename contains 'password'"),
]

SUSPICIOUS_CONTENT_PATTERNS = [
    (b"<script", "Contains HTML script tags"),
    (b"javascript:", "Contains javascript: URI"),
    (b"eval(", "Contains eval() call"),
    (b"exec(", "Contains exec() call"),
    (b"subprocess", "Contains subprocess reference"),
    (b"os.system", "Contains os.system() call"),
    (b"__import__", "Contains __import__() call"),
    (b"importlib", "Contains importlib reference"),
    (b"powershell", "Contains PowerShell reference"),
    (b"cmd.exe", "Contains cmd.exe reference"),
    (b"base64", "Contains base64 encoding"),
    (b"\\x", "Contains hex escape sequences"),
]

MIME_TYPE_EXTENSIONS_MAP = {
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
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".avi": "video/x-msvideo",
    ".mov": "video/quicktime",
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
    ".7z": "application/x-7z-compressed",
}


def _rule_executable_extension(analysis: dict) -> RuleResult:
    ext = analysis.get("extension", "").lower()
    detected = ext in EXECUTABLE_EXTENSIONS
    return RuleResult(
        name="Executable Extension",
        description=f"File has executable extension '{ext}'." if detected else f"File extension '{ext}' is not a known executable type.",
        severity="critical" if detected else "none",
        points=25 if detected else 0,
        detected=detected,
    )


def _rule_script_extension(analysis: dict) -> RuleResult:
    ext = analysis.get("extension", "").lower()
    detected = ext in SCRIPT_EXTENSIONS
    return RuleResult(
        name="Script Extension",
        description=f"File has script extension '{ext}'." if detected else f"File extension '{ext}' is not a known script type.",
        severity="critical" if detected else "none",
        points=20 if detected else 0,
        detected=detected,
    )


def _rule_double_extension(analysis: dict) -> RuleResult:
    filename = analysis.get("filename", "")
    parts = filename.split(".")
    detected = len(parts) > 2
    description = "Filename contains multiple extensions."
    if detected:
        ext_sequence = ".".join(parts[1:])
        description = f"Filename contains multiple extensions: '.{ext_sequence}'."
    return RuleResult(
        name="Double Extension",
        description=description,
        severity="warning" if detected else "none",
        points=30 if detected else 0,
        detected=detected,
    )


def _rule_extension_mismatch(analysis: dict) -> RuleResult:
    ext = analysis.get("extension", "").lower()
    mime = analysis.get("mime_type", "")
    detected_type = analysis.get("metadata", {}).get("detected_type", "")

    expected_mime = MIME_TYPE_EXTENSIONS_MAP.get(ext)

    if not expected_mime:
        return RuleResult(
            name="Extension Mismatch",
            description=f"Cannot verify extension '{ext}' against known MIME types.",
            severity="info",
            points=0,
            detected=False,
        )

    mime_mismatch = expected_mime != mime
    type_category_mismatch = False
    if detected_type and ext:
        type_ext_map = {
            "image": {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".ico", ".tiff"},
            "document": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"},
            "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"},
            "audio": {".mp3", ".wav", ".ogg", ".flac", ".aac"},
            "video": {".mp4", ".avi", ".mov", ".mkv", ".wmv"},
            "text": {".txt", ".html", ".css", ".js", ".json", ".xml", ".csv", ".md", ".py", ".java"},
        }
        expected_types = type_ext_map.get(detected_type, set())
        type_category_mismatch = ext not in expected_types and expected_types != set()

    detected = mime_mismatch or type_category_mismatch
    parts = []
    if mime_mismatch:
        parts.append(f"Extension '{ext}' expects MIME '{expected_mime}', but detected '{mime}'")
    if type_category_mismatch:
        parts.append(f"Detected type '{detected_type}' does not match extension '{ext}'")
    description = "; ".join(parts) if parts else "No mismatch detected."

    return RuleResult(
        name="Extension Mismatch",
        description=description,
        severity="warning" if detected else "none",
        points=30 if detected else 0,
        detected=detected,
    )


def _rule_suspicious_filename(analysis: dict) -> RuleResult:
    filename = analysis.get("filename", "")
    matches = []
    for pattern, desc in SUSPICIOUS_FILENAME_PATTERNS:
        if re.search(pattern, filename):
            matches.append(desc)

    detected = len(matches) > 0
    description = "No suspicious filename characteristics detected."
    if detected:
        description = "Suspicious filename characteristics: " + "; ".join(matches)

    return RuleResult(
        name="Suspicious Filename",
        description=description,
        severity="warning" if detected else "none",
        points=10 if detected else 0,
        detected=detected,
    )


def _rule_file_type_characteristics(analysis: dict) -> RuleResult:
    detected_type = analysis.get("metadata", {}).get("detected_type", "")
    detected_subtype = analysis.get("metadata", {}).get("detected_subtype", "")
    mime = analysis.get("mime_type", "")
    ext = analysis.get("extension", "").lower()

    suspicious = False
    reasons = []

    if detected_type == "unknown":
        suspicious = True
        reasons.append("File type could not be determined from content")

    if detected_subtype == "empty":
        suspicious = True
        reasons.append("File content appears empty")

    if ext in EXECUTABLE_EXTENSIONS and detected_type != "unknown":
        if detected_type not in ("archive",):
            suspicious = True
            reasons.append(f"Executable extension '{ext}' with non-archive content type '{detected_type}'")

    if detected_subtype == "ole" and ext not in (".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx"):
        suspicious = True
        reasons.append("OLE/COM document format detected with non-document extension")

    description = "No suspicious file-type characteristics detected."
    if suspicious:
        description = "File-type characteristics: " + "; ".join(reasons)

    return RuleResult(
        name="File-Type Characteristics",
        description=description,
        severity="warning" if suspicious else "none",
        points=15 if suspicious else 0,
        detected=suspicious,
    )


def _rule_file_size_characteristics(analysis: dict) -> RuleResult:
    file_size = analysis.get("file_size", 0)
    ext = analysis.get("extension", "").lower()

    suspicious = False
    reasons = []

    if file_size == 0:
        suspicious = True
        reasons.append("File is empty (0 bytes)")

    if ext in EXECUTABLE_EXTENSIONS and file_size < 1024:
        suspicious = True
        reasons.append(f"Executable file '{ext}' is unusually small ({file_size} bytes)")

    if ext in ARCHIVE_EXTENSIONS and file_size > 100 * 1024 * 1024:
        suspicious = True
        reasons.append(f"Archive file is very large ({file_size / (1024*1024):.1f} MB)")

    description = "No suspicious file-size characteristics detected."
    if suspicious:
        description = "File-size characteristics: " + "; ".join(reasons)

    return RuleResult(
        name="File-Size Characteristics",
        description=description,
        severity="warning" if suspicious else "none",
        points=10 if suspicious else 0,
        detected=suspicious,
    )


def _rule_content_patterns(analysis: dict) -> RuleResult:
    indicators = analysis.get("indicators", [])
    detected = len(indicators) > 0

    description = "No suspicious content patterns detected."
    if detected:
        description = "Content patterns found: " + "; ".join(indicators)

    return RuleResult(
        name="Content Patterns",
        description=description,
        severity="warning" if detected else "none",
        points=15 if detected else 0,
        detected=detected,
    )


ALL_RULES = [
    _rule_executable_extension,
    _rule_script_extension,
    _rule_double_extension,
    _rule_extension_mismatch,
    _rule_suspicious_filename,
    _rule_file_type_characteristics,
    _rule_file_size_characteristics,
    _rule_content_patterns,
]


def run_all_rules(analysis: dict) -> list[RuleResult]:
    return [rule(analysis) for rule in ALL_RULES]
