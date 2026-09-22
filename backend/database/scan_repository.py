from datetime import datetime, timezone
from sqlalchemy import func, or_, desc, asc
from database.db import get_session, close_session
from models.scan import ScanResult


def create_scan(data: dict) -> dict:
    session = get_session()
    try:
        scan = ScanResult(
            filename=data["filename"],
            extension=data.get("extension", ""),
            file_type=data.get("file_type", "unknown"),
            mime_type=data.get("mime_type", "application/octet-stream"),
            file_size=data.get("file_size", 0),
            md5=data.get("md5", ""),
            sha256=data.get("sha256", ""),
            risk_score=data.get("risk_score", 0),
            risk_level=data.get("risk_level", "unknown"),
            scan_timestamp=datetime.now(timezone.utc),
        )
        scan.set_indicators(data.get("indicators", []))
        scan.set_metadata(data.get("metadata", {}))

        session.add(scan)
        session.commit()
        result = scan.to_dict()
        return result
    except Exception as e:
        session.rollback()
        raise e
    finally:
        close_session(session)


def get_scan(scan_id: int) -> dict | None:
    session = get_session()
    try:
        scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
        return scan.to_dict() if scan else None
    except Exception:
        return None
    finally:
        close_session(session)


def get_all_scans(page: int = 1, per_page: int = 20, sort_by: str = "scan_timestamp", order: str = "desc") -> dict:
    session = get_session()
    ALLOWED_SORT_COLUMNS = {"scan_timestamp", "filename", "risk_score", "risk_level", "file_size", "id"}
    try:
        if sort_by not in ALLOWED_SORT_COLUMNS:
            sort_by = "scan_timestamp"
        sort_column = getattr(ScanResult, sort_by, ScanResult.scan_timestamp)
        sort_func = desc(sort_column) if order == "desc" else asc(sort_column)

        total = session.query(func.count(ScanResult.id)).scalar()
        scans = (
            session.query(ScanResult)
            .order_by(sort_func)
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "scans": [s.to_dict() for s in scans],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, -(-total // per_page)),
        }
    except Exception:
        return {"scans": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}
    finally:
        close_session(session)


def search_scans(query: str, page: int = 1, per_page: int = 20) -> dict:
    session = get_session()
    try:
        search = f"%{query}%"
        filter_cond = or_(
            ScanResult.filename.ilike(search),
            ScanResult.file_type.ilike(search),
            ScanResult.sha256.ilike(search),
            ScanResult.md5.ilike(search),
        )

        total = session.query(func.count(ScanResult.id)).filter(filter_cond).scalar()
        scans = (
            session.query(ScanResult)
            .filter(filter_cond)
            .order_by(desc(ScanResult.scan_timestamp))
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "scans": [s.to_dict() for s in scans],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, -(-total // per_page)),
        }
    except Exception:
        return {"scans": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}
    finally:
        close_session(session)


def get_scans_by_risk_level(risk_level: str, page: int = 1, per_page: int = 20) -> dict:
    session = get_session()
    try:
        total = session.query(func.count(ScanResult.id)).filter(ScanResult.risk_level == risk_level).scalar()
        scans = (
            session.query(ScanResult)
            .filter(ScanResult.risk_level == risk_level)
            .order_by(desc(ScanResult.scan_timestamp))
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )

        return {
            "scans": [s.to_dict() for s in scans],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, -(-total // per_page)),
        }
    except Exception:
        return {"scans": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}
    finally:
        close_session(session)


def get_risk_level_counts() -> dict:
    session = get_session()
    try:
        results = (
            session.query(ScanResult.risk_level, func.count(ScanResult.id))
            .group_by(ScanResult.risk_level)
            .all()
        )
        return {level: count for level, count in results}
    except Exception:
        return {}
    finally:
        close_session(session)


def get_scan_activity() -> list[dict]:
    session = get_session()
    try:
        scan_activity = (
            session.query(
                func.strftime("%Y-%m-%d", ScanResult.scan_timestamp).label("date"),
                func.count(ScanResult.id).label("count"),
            )
            .group_by("date")
            .order_by("date")
            .all()
        )
        return [{"date": row.date, "count": row.count} for row in scan_activity]
    except Exception:
        return []
    finally:
        close_session(session)
