import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

CLAMAV_ENABLED = os.getenv("CLAMAV_ENABLED", "true").lower() == "true"
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "127.0.0.1")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))


def _get_clamd_connection():
    """Get a pyclamd connection instance."""
    try:
        import pyclamd
        cd = pyclamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT)
        cd.ping()
        return cd
    except Exception as e:
        logger.warning(f"ClamAV connection failed: {e}")
        return None


def scan_file_with_clamav(file_path: str) -> Dict[str, Any]:
    """Scan a file using ClamAV antivirus engine.

    Returns dict with:
        - scanned: bool - whether scan was performed
        - is_infected: bool - whether malware was detected
        - virus_name: str or None - name of detected threat
        - scan_result: str - 'clean', 'infected', or 'error'
        - engine_version: str - ClamAV engine version
        - db_version: str - virus database version
        - details: dict - raw scan output
    """
    result = {
        "scanned": False,
        "is_infected": False,
        "virus_name": None,
        "scan_result": "error",
        "engine_version": "",
        "db_version": "",
        "details": {},
    }

    if not CLAMAV_ENABLED:
        result["scan_result"] = "skipped"
        logger.info("ClamAV scanning disabled via CLAMAV_ENABLED=false")
        return result

    if not os.path.isfile(file_path):
        result["details"]["error"] = f"File not found: {file_path}"
        return result

    try:
        cd = _get_clamd_connection()
        if cd is None:
            result["details"]["error"] = "Could not connect to ClamAV daemon"
            result["details"]["hint"] = (
                "Ensure clamd is running. On Windows: "
                "1) Install ClamAV from https://www.clamav.net/downloads "
                "2) Run freshclam.exe to update virus DB "
                "3) Run: clamd --install-service && net start clamd"
            )
            return result

        scan_result = cd.scan_file(file_path)
        result["scanned"] = True

        if scan_result is None:
            result["scan_result"] = "clean"
            result["is_infected"] = False
        else:
            result["scan_result"] = "infected"
            result["is_infected"] = True
            if isinstance(scan_result, dict) and "stream" in scan_result:
                result["virus_name"] = scan_result["stream"]
            elif isinstance(scan_result, tuple) and len(scan_result) >= 2:
                result["virus_name"] = scan_result[1]
            else:
                result["virus_name"] = str(scan_result)

        try:
            version_info = cd.version()
            if version_info:
                result["engine_version"] = str(version_info.get("engine", ""))
                result["db_version"] = str(version_info.get("db", ""))
        except Exception:
            pass

    except Exception as e:
        logger.error(f"ClamAV scan failed for {file_path}: {e}")
        result["details"]["error"] = str(e)
        result["scan_result"] = "error"

    return result


def scan_data_with_clamav(data: bytes) -> Dict[str, Any]:
    """Scan in-memory data using ClamAV."""
    result = {
        "scanned": False,
        "is_infected": False,
        "virus_name": None,
        "scan_result": "error",
        "details": {},
    }

    if not CLAMAV_ENABLED:
        result["scan_result"] = "skipped"
        return result

    try:
        cd = _get_clamd_connection()
        if cd is None:
            result["details"]["error"] = "Could not connect to ClamAV daemon"
            return result

        scan_result = cd.scan_data(data)
        result["scanned"] = True

        if scan_result is None:
            result["scan_result"] = "clean"
        else:
            result["scan_result"] = "infected"
            result["is_infected"] = True
            if isinstance(scan_result, dict) and "stream" in scan_result:
                result["virus_name"] = scan_result["stream"]
            elif isinstance(scan_result, tuple) and len(scan_result) >= 2:
                result["virus_name"] = scan_result[1]

    except Exception as e:
        logger.error(f"ClamAV data scan failed: {e}")
        result["details"]["error"] = str(e)

    return result


def get_clamav_status() -> Dict[str, Any]:
    """Check ClamAV daemon status and version info."""
    status = {
        "available": False,
        "enabled": CLAMAV_ENABLED,
        "host": CLAMAV_HOST,
        "port": CLAMAV_PORT,
        "engine_version": "",
        "db_version": "",
    }

    if not CLAMAV_ENABLED:
        return status

    try:
        cd = _get_clamd_connection()
        if cd is not None:
            status["available"] = True
            try:
                version_info = cd.version()
                if version_info:
                    status["engine_version"] = str(version_info.get("engine", ""))
                    status["db_version"] = str(version_info.get("db", ""))
            except Exception:
                pass
    except Exception:
        pass

    return status
