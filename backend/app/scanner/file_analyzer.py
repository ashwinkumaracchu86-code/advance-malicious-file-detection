import os
import json
import logging
from typing import Dict, Any, Optional

from .hash_calculator import calculate_hashes
from .mime_detector import get_file_info
from .entropy_analyzer import calculate_shannon_entropy
from .string_analyzer import extract_suspicious_strings

from .clamav_scanner import scan_file_with_clamav
from .risk_scorer import calculate_risk_score

logger = logging.getLogger(__name__)


def analyze_file(file_path: str, vt_results: Optional[Dict] = None) -> Dict[str, Any]:
    """Perform comprehensive analysis of a file.

    Orchestrates all scanning modules to produce a complete analysis result.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    result = {
        "file_path": file_path,
        "file_size": os.path.getsize(file_path),
        "analysis_complete": False,
        "errors": [],
    }

    # 1. Hash calculation
    try:
        hashes = calculate_hashes(file_path)
        result.update(hashes)
    except Exception as e:
        logger.error(f"Hash calculation failed: {e}")
        result["errors"].append(f"Hash calculation: {str(e)}")
        result["md5"] = ""
        result["sha1"] = ""
        result["sha256"] = ""

    # 2. MIME detection
    try:
        mime_info = get_file_info(file_path)
        result["mime_type"] = mime_info["mime_type"]
        result["extension"] = mime_info["extension"]
        result["extension_matches_mime"] = mime_info["extension_matches_mime"]
        result["file_signature"] = mime_info.get("file_signature")
        result["is_suspicious_mime"] = mime_info["is_suspicious_mime"]
    except Exception as e:
        logger.error(f"MIME detection failed: {e}")
        result["errors"].append(f"MIME detection: {str(e)}")
        result["mime_type"] = "application/octet-stream"
        result["extension"] = os.path.splitext(file_path)[1]
        result["extension_matches_mime"] = True
        result["file_signature"] = None
        result["is_suspicious_mime"] = False

    # 3. Entropy analysis
    try:
        entropy_data = calculate_shannon_entropy(file_path)
        result["entropy"] = entropy_data["entropy"]
    except Exception as e:
        logger.error(f"Entropy analysis failed: {e}")
        result["errors"].append(f"Entropy analysis: {str(e)}")
        result["entropy"] = 0.0

    # 4. String analysis
    try:
        string_data = extract_suspicious_strings(file_path)
        result["suspicious_strings"] = string_data["suspicious_strings"]
        result["suspicious_strings_count"] = string_data["count"]
        result["string_details"] = string_data.get("details", {})
    except Exception as e:
        logger.error(f"String analysis failed: {e}")
        result["errors"].append(f"String analysis: {str(e)}")
        result["suspicious_strings"] = []
        result["suspicious_strings_count"] = 0
        result["string_details"] = {}

    # 5. ClamAV antivirus scanning
    try:
        clamav_data = scan_file_with_clamav(file_path)
        result["clamav_scanned"] = clamav_data["scanned"]
        result["clamav_is_infected"] = clamav_data["is_infected"]
        result["clamav_virus_name"] = clamav_data["virus_name"]
        result["clamav_scan_result"] = clamav_data["scan_result"]
        result["clamav_engine_version"] = clamav_data.get("engine_version", "")
        result["clamav_db_version"] = clamav_data.get("db_version", "")
    except Exception as e:
        logger.error(f"ClamAV scanning failed: {e}")
        result["errors"].append(f"ClamAV scanning: {str(e)}")
        result["clamav_scanned"] = False
        result["clamav_is_infected"] = False
        result["clamav_virus_name"] = None
        result["clamav_scan_result"] = "error"
        result["clamav_engine_version"] = ""
        result["clamav_db_version"] = ""

    # 6. VirusTotal results (if provided)
    vt_positives = 0
    vt_total = 0
    if vt_results:
        vt_positives = vt_results.get("positives", 0)
        vt_total = vt_results.get("total", 0)
    result["vt_positives"] = vt_positives
    result["vt_total"] = vt_total

    # 7. Risk scoring
    try:
        risk_data = calculate_risk_score(
            entropy=result["entropy"],
            suspicious_count=result["suspicious_strings_count"],

            extension=result["extension"],
            mime_type=result["mime_type"],
            extension_matches_mime=result["extension_matches_mime"],
            file_size=result["file_size"],
            vt_positives=vt_positives,
            vt_total=vt_total,
            clamav_is_infected=result["clamav_is_infected"],
            clamav_scan_result=result["clamav_scan_result"],
        )
        result["risk_score"] = risk_data["risk_score"]
        result["classification"] = risk_data["classification"]
        result["detection_reasons"] = risk_data["reasons"]
        result["factor_breakdown"] = risk_data["factor_breakdown"]
    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        result["errors"].append(f"Risk scoring: {str(e)}")
        result["risk_score"] = 0.0
        result["classification"] = "unknown"
        result["detection_reasons"] = ["Analysis failed - unable to calculate risk score"]
        result["factor_breakdown"] = {}

    result["analysis_complete"] = len(result["errors"]) == 0

    return result


def quick_scan(file_path: str) -> Dict[str, Any]:
    """Perform a quick scan with limited analysis for fast results."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    result = {
        "file_path": file_path,
        "file_size": os.path.getsize(file_path),
    }

    hashes = calculate_hashes(file_path)
    result.update(hashes)

    mime_info = get_file_info(file_path)
    result["mime_type"] = mime_info["mime_type"]
    result["extension"] = mime_info["extension"]
    result["is_suspicious_mime"] = mime_info["is_suspicious_mime"]

    return result
