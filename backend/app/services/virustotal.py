import os
import logging
import time
from typing import Optional, Dict, Any

import requests

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def is_configured() -> bool:
    """Check if VirusTotal API key is configured."""
    return bool(VIRUSTOTAL_API_KEY)


def query_hash(file_hash: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for a file hash.

    Returns detection results or None if not configured / error occurred.
    """
    if not is_configured():
        logger.info("VirusTotal API key not configured. Skipping VT query.")
        return None

    if not file_hash or len(file_hash) < 32:
        logger.warning("Invalid hash provided for VT query.")
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    url = f"{VT_BASE_URL}/files/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit exceeded. Retrying after delay.")
            time.sleep(15)
            response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 404:
            logger.info(f"File {file_hash} not found on VirusTotal.")
            return {
                "found": False,
                "hash": file_hash,
                "message": "File not found on VirusTotal",
            }

        if response.status_code != 200:
            logger.warning(f"VirusTotal API returned status {response.status_code}")
            return None

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        undetected_count = stats.get("undetected", 0)
        total_engines = sum(stats.values())

        result = {
            "found": True,
            "hash": file_hash,
            "positives": malicious_count + suspicious_count,
            "total": total_engines,
            "detection_rate": round(
                (malicious_count + suspicious_count) / total_engines * 100, 2
            ) if total_engines > 0 else 0,
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "undetected": undetected_count,
            "file_type": attributes.get("type_description", ""),
            "file_size": attributes.get("size", 0),
            "names": attributes.get("names", [])[:10],
            "reputation": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date", 0),
        }

        return result

    except requests.exceptions.Timeout:
        logger.error("VirusTotal API request timed out.")
        return None
    except requests.exceptions.ConnectionError:
        logger.error("Failed to connect to VirusTotal API.")
        return None
    except Exception as e:
        logger.error(f"VirusTotal query failed: {e}")
        return None


def query_url(url_to_check: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for a URL analysis."""
    if not is_configured():
        return None

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    }

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
        response = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=30,
        )

        if response.status_code == 404:
            return {"found": False, "url": url_to_check}
        if response.status_code != 200:
            return None

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "found": True,
            "url": url_to_check,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total": sum(stats.values()),
        }

    except Exception as e:
        logger.error(f"VT URL query failed: {e}")
        return None
