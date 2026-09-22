import os
import zipfile
import tarfile
import hashlib
import logging
import tempfile
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.vbs', '.vbe', '.js',
    '.jse', '.wsf', '.wsh', '.ps1', '.psm1', '.psd1', '.msc', '.msp',
    '.mst', '.pif', '.hta', '.cpl', '.inf', '.reg', '.rgs', '.sct',
    '.shb', '.shs', '.lnk', '.application', '.gadget', '.webpnp',
    '.xnk', '.settingcontent-ms', '.library-ms', '.searchConnector-ms',
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.ppsm', '.potm', '.sldm',
}

MAX_ARCHIVE_SIZE_MB = 100
MAX_EXTRACTED_SIZE_MB = 500
MAX_FILES_IN_ARCHIVE = 500
MAX_RECURSION_DEPTH = 3


def get_file_hashes(file_path: str) -> Dict[str, str]:
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha1"] = sha1.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        logger.error(f"Hash calculation error: {e}")
    return hashes


def analyze_single_file(file_path: str, filename: str) -> Dict[str, Any]:
    ext = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    reasons = []
    score = 0.0

    is_dangerous = ext in DANGEROUS_EXTENSIONS
    if is_dangerous:
        reasons.append(f"Dangerous file extension: {ext}")
        score += 30

    parts = filename.split('.')
    if len(parts) > 2:
        second_ext = '.' + parts[-2].lower()
        if second_ext in DANGEROUS_EXTENSIONS or ext in DANGEROUS_EXTENSIONS:
            reasons.append(f"Double extension detected: {filename}")
            score += 25

    suspicious_names = ['invoice', 'receipt', 'payment', 'document', 'photo', 'image', 'scan']
    name_lower = filename.lower()
    for sname in suspicious_names:
        if sname in name_lower and is_dangerous:
            reasons.append(f"Social engineering filename pattern: '{sname}' with executable extension")
            score += 15
            break

    if size == 0:
        reasons.append("Empty file in archive")
        score += 10
    elif size > 100 * 1024 * 1024:
        reasons.append(f"Unusually large file in archive ({size / (1024*1024):.1f} MB)")
        score += 10

    script_extensions = {'.js', '.vbs', '.vbe', '.wsf', '.wsh', '.ps1', '.bat', '.cmd', '.sh'}
    if ext in script_extensions:
        reasons.append(f"Script file in archive: {ext}")
        score += 20

    score = min(100.0, score)

    if score >= 60:
        classification = "malicious"
    elif score >= 30:
        classification = "suspicious"
    elif score >= 15:
        classification = "low_risk"
    else:
        classification = "safe"

    return {
        "filename": filename,
        "extension": ext,
        "size": size,
        "is_dangerous_extension": is_dangerous,
        "reasons": reasons,
        "risk_score": round(score, 2),
        "classification": classification,
    }


def analyze_zip_archive(file_path: str) -> Dict[str, Any]:
    result = {
        "archive_type": "zip",
        "is_valid": False,
        "files": [],
        "total_files": 0,
        "total_size": 0,
        "threats_found": 0,
        "risk_score": 0.0,
        "classification": "safe",
        "reasons": [],
        "errors": [],
    }

    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_ARCHIVE_SIZE_MB * 1024 * 1024:
            result["reasons"].append(f"Archive exceeds maximum size limit ({MAX_ARCHIVE_SIZE_MB} MB)")
            result["risk_score"] = 50.0
            result["classification"] = "suspicious"
            return result

        with zipfile.ZipFile(file_path, 'r') as zf:
            result["is_valid"] = True
            file_list = zf.namelist()

            if len(file_list) > MAX_FILES_IN_ARCHIVE:
                result["reasons"].append(f"Archive contains too many files ({len(file_list)} > {MAX_FILES_IN_ARCHIVE})")
                result["risk_score"] = 40.0
                result["classification"] = "suspicious"
                return result

            total_extracted_size = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue

                total_extracted_size += info.file_size
                if total_extracted_size > MAX_EXTRACTED_SIZE_MB * 1024 * 1024:
                    result["reasons"].append("Archive extraction would exceed size limit (possible archive bomb)")
                    result["risk_score"] = 70.0
                    result["classification"] = "malicious"
                    return result

                analysis = analyze_single_file(file_path, info.filename)
                analysis["compressed_size"] = info.compress_size
                analysis["uncompressed_size"] = info.file_size
                result["files"].append(analysis)
                result["total_size"] += info.file_size

            result["total_files"] = len(result["files"])
            result["threats_found"] = sum(1 for f in result["files"] if f["classification"] in ("malicious", "suspicious"))

            if result["files"]:
                max_score = max(f["risk_score"] for f in result["files"])
                result["risk_score"] = max_score

            has_password = False
            try:
                zf.extractall(tempfile.gettempdir())
            except RuntimeError as e:
                if "password" in str(e).lower() or "Bad password" in str(e):
                    has_password = True
                    result["reasons"].append("Archive is password-protected")
                    result["risk_score"] = max(result["risk_score"], 25.0)
            except Exception:
                pass

            result["is_password_protected"] = has_password

            for f in result["files"]:
                result["reasons"].extend(f.get("reasons", []))

    except zipfile.BadZipFile:
        result["errors"].append("Invalid or corrupted ZIP archive")
    except Exception as e:
        result["errors"].append(f"ZIP analysis error: {str(e)}")

    score = result["risk_score"]
    if score >= 60:
        result["classification"] = "malicious"
    elif score >= 30:
        result["classification"] = "suspicious"
    elif score >= 15:
        result["classification"] = "low_risk"
    else:
        result["classification"] = "safe"

    return result


def analyze_tar_archive(file_path: str) -> Dict[str, Any]:
    result = {
        "archive_type": "tar",
        "is_valid": False,
        "files": [],
        "total_files": 0,
        "total_size": 0,
        "threats_found": 0,
        "risk_score": 0.0,
        "classification": "safe",
        "reasons": [],
        "errors": [],
    }

    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_ARCHIVE_SIZE_MB * 1024 * 1024:
            result["reasons"].append(f"Archive exceeds maximum size limit ({MAX_ARCHIVE_SIZE_MB} MB)")
            result["risk_score"] = 50.0
            result["classification"] = "suspicious"
            return result

        with tarfile.open(file_path, 'r:*') as tf:
            result["is_valid"] = True
            members = tf.getmembers()

            if len(members) > MAX_FILES_IN_ARCHIVE:
                result["reasons"].append(f"Archive contains too many files ({len(members)} > {MAX_FILES_IN_ARCHIVE})")
                result["risk_score"] = 40.0
                result["classification"] = "suspicious"
                return result

            total_extracted_size = 0
            for member in members:
                if not member.isfile():
                    continue

                total_extracted_size += member.size
                if total_extracted_size > MAX_EXTRACTED_SIZE_MB * 1024 * 1024:
                    result["reasons"].append("Archive extraction would exceed size limit (possible archive bomb)")
                    result["risk_score"] = 70.0
                    result["classification"] = "malicious"
                    return result

                if member.name.startswith('/') or '..' in member.name:
                    result["reasons"].append(f"Path traversal attempt in archive: {member.name}")
                    result["risk_score"] = 80.0
                    result["classification"] = "malicious"
                    return result

                analysis = analyze_single_file(file_path, os.path.basename(member.name))
                analysis["uncompressed_size"] = member.size
                result["files"].append(analysis)
                result["total_size"] += member.size

            result["total_files"] = len(result["files"])
            result["threats_found"] = sum(1 for f in result["files"] if f["classification"] in ("malicious", "suspicious"))

            if result["files"]:
                max_score = max(f["risk_score"] for f in result["files"])
                result["risk_score"] = max_score

            for f in result["files"]:
                result["reasons"].extend(f.get("reasons", []))

    except tarfile.TarError:
        result["errors"].append("Invalid or corrupted TAR archive")
    except Exception as e:
        result["errors"].append(f"TAR analysis error: {str(e)}")

    score = result["risk_score"]
    if score >= 60:
        result["classification"] = "malicious"
    elif score >= 30:
        result["classification"] = "suspicious"
    elif score >= 15:
        result["classification"] = "low_risk"
    else:
        result["classification"] = "safe"

    return result


def analyze_archive(file_path: str) -> Dict[str, Any]:
    ext = os.path.splitext(file_path)[1].lower()

    if ext == '.zip':
        return analyze_zip_archive(file_path)
    elif ext in ('.tar', '.tgz', '.tar.gz', '.tar.bz2', '.tar.xz'):
        return analyze_tar_archive(file_path)
    else:
        try:
            if zipfile.is_zipfile(file_path):
                return analyze_zip_archive(file_path)
        except Exception:
            pass

        return {
            "archive_type": "unknown",
            "is_valid": False,
            "files": [],
            "total_files": 0,
            "total_size": 0,
            "threats_found": 0,
            "risk_score": 0.0,
            "classification": "unknown",
            "reasons": [],
            "errors": [f"Unsupported archive format: {ext}"],
        }
