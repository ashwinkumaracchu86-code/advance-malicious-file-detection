from analyzers.file_analyzer import analyze_file
from services.risk_engine import evaluate_risk
from database import create_scan, get_scan, get_all_scans, search_scans, get_scans_by_risk_level


def process_upload(file_storage, max_upload_size: int = 0) -> dict:
    analysis = analyze_file(file_storage, max_upload_size)

    risk = evaluate_risk(analysis)

    scan_record = create_scan({
        "filename": analysis["filename"],
        "extension": analysis["extension"],
        "file_type": analysis["file_type"],
        "mime_type": analysis["mime_type"],
        "file_size": analysis["file_size"],
        "md5": analysis["md5"],
        "sha256": analysis["sha256"],
        "risk_score": risk["score"],
        "risk_level": risk["risk_level"],
        "indicators": risk["indicators"],
        "metadata": {
            **analysis["metadata"],
            "explanation": risk["explanation"],
        },
    })

    return {
        "scan": scan_record,
        "explanation": risk["explanation"],
    }


def get_scan_detail(scan_id: int) -> dict | None:
    return get_scan(scan_id)


def list_scans(
    search: str = "",
    risk: str = "",
    sort: str = "scan_timestamp",
    order: str = "desc",
    page: int = 1,
    limit: int = 20,
) -> dict:
    if risk:
        return get_scans_by_risk_level(risk.upper(), page=page, per_page=limit)
    if search:
        return search_scans(search, page=page, per_page=limit)
    return get_all_scans(page=page, per_page=limit, sort_by=sort, order=order)
