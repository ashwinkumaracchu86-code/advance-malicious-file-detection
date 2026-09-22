import os
import json
import math
from typing import Dict, List, Any


DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".msc", ".msp",
    ".mst", ".pif", ".hta", ".cpl", ".inf", ".reg", ".rgs", ".sct",
    ".shb", ".shs", ".lnk", ".application", ".gadget", ".webpnp",
    ".xnk", ".settingcontent-ms", ".library-ms", ".searchConnector-ms",
}

MODERATE_RISK_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
    ".rtf", ".odt", ".ods", ".odp", ".pdf", ".swf",
}

SAFE_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".html", ".css", ".js",
    ".py", ".java", ".c", ".cpp", ".h", ".hpp", ".rb", ".go",
    ".rs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".flac", ".ogg", ".avi", ".mkv", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
}


def calculate_risk_score(
    entropy: float,
    suspicious_count: int,
    extension: str,
    mime_type: str,
    extension_matches_mime: bool,
    file_size: int,
    vt_positives: int = 0,
    vt_total: int = 0,
    clamav_is_infected: bool = False,
    clamav_scan_result: str = "unknown",
) -> Dict[str, any]:
    """Calculate a risk score from 0 to 100 based on multiple factors.

    Factors:
    - Entropy (0-20 points): High entropy may indicate packed/encrypted content.
    - Suspicious strings (0-20 points): Suspicious patterns found in file.
    - Extension danger (0-15 points): File extension risk level.
    - MIME mismatch (0-10 points): Extension does not match MIME type.
    - File size anomalies (0-5 points): Very small or very large files.
    - VirusTotal (0-5 points): External detection results.
    - ClamAV (0-15 points): Antivirus engine detection.
    """
    score = 0.0
    reasons = []

    # 1. Entropy analysis (0-20 points)
    if entropy >= 7.0:
        score += 20
        reasons.append(f"Very high entropy ({entropy:.2f}) suggests packed/encrypted content")
    elif entropy >= 6.5:
        score += 15
        reasons.append(f"High entropy ({entropy:.2f}) may indicate obfuscation")
    elif entropy >= 5.0:
        score += 8
        reasons.append(f"Medium-high entropy ({entropy:.2f})")
    elif entropy < 1.0:
        score += 5
        reasons.append(f"Very low entropy ({entropy:.2f}) may indicate zero-filled or padded file")

    # 2. Suspicious strings (0-20 points)
    if suspicious_count >= 10:
        score += 20
        reasons.append(f"High count of suspicious strings ({suspicious_count})")
    elif suspicious_count >= 5:
        score += 12
        reasons.append(f"Moderate suspicious strings found ({suspicious_count})")
    elif suspicious_count >= 1:
        score += 5
        reasons.append(f"Some suspicious strings detected ({suspicious_count})")

    # 3. Extension danger (0-15 points)
    ext_lower = extension.lower() if extension else ""
    if ext_lower in DANGEROUS_EXTENSIONS:
        score += 15
        reasons.append(f"Dangerous file extension ({ext_lower})")
    elif ext_lower in MODERATE_RISK_EXTENSIONS:
        score += 7
        reasons.append(f"Moderate-risk file extension ({ext_lower})")

    # 4. MIME mismatch (0-10 points)
    if not extension_matches_mime:
        score += 10
        reasons.append(f"Extension {ext_lower} does not match MIME type {mime_type}")

    # 5. File size anomalies (0-5 points)
    if file_size == 0:
        score += 3
        reasons.append("Empty file (0 bytes)")
    elif file_size < 100:
        score += 2
        reasons.append("Very small file size")
    elif file_size > 100 * 1024 * 1024:
        score += 3
        reasons.append("Unusually large file size (>100MB)")

    # 6. VirusTotal results (0-5 points)
    if vt_total > 0:
        ratio = vt_positives / vt_total
        if ratio >= 0.5:
            score += 5
            reasons.append(f"High VirusTotal detection rate ({vt_positives}/{vt_total})")
        elif ratio >= 0.2:
            score += 3
            reasons.append(f"Moderate VirusTotal detection ({vt_positives}/{vt_total})")
        elif ratio > 0:
            score += 1
            reasons.append(f"Low VirusTotal detection ({vt_positives}/{vt_total})")

    # 7. ClamAV results (0-15 points)
    if clamav_is_infected:
        score += 15
        reasons.append("ClamAV detected malware in file")
    elif clamav_scan_result == "clean":
        pass  # No additional points for clean scan
    elif clamav_scan_result == "error":
        reasons.append("ClamAV scan could not complete")

    score = min(100.0, max(0.0, score))

    # Classification
    if score >= 70:
        classification = "malicious"
    elif score >= 40:
        classification = "suspicious"
    elif score >= 15:
        classification = "low_risk"
    else:
        classification = "safe"

    return {
        "risk_score": round(score, 2),
        "classification": classification,
        "reasons": reasons,
        "factor_breakdown": {
            "entropy_score": 20 if entropy >= 7.0 else (15 if entropy >= 6.5 else (8 if entropy >= 5.0 else (5 if entropy < 1.0 else 0))),
            "suspicious_strings_score": 20 if suspicious_count >= 10 else (12 if suspicious_count >= 5 else (5 if suspicious_count >= 1 else 0)),
            "extension_score": 15 if ext_lower in DANGEROUS_EXTENSIONS else (7 if ext_lower in MODERATE_RISK_EXTENSIONS else 0),
            "mismatch_score": 10 if not extension_matches_mime else 0,
            "size_score": 3 if file_size == 0 else (2 if file_size < 100 else (3 if file_size > 100 * 1024 * 1024 else 0)),
            "vt_score": 5 if vt_total > 0 and vt_positives / vt_total >= 0.5 else (3 if vt_total > 0 and vt_positives / vt_total >= 0.2 else (1 if vt_total > 0 and vt_positives > 0 else 0)),
            "clamav_score": 15 if clamav_is_infected else 0,
        },
    }
