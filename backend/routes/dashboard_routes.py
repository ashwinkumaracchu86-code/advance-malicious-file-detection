from flask import Blueprint, jsonify
from database import get_risk_level_counts, get_all_scans, get_scan_activity


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    try:
        risk_counts = get_risk_level_counts()

        total = sum(risk_counts.values())
        low = risk_counts.get("LOW", 0)
        suspicious = risk_counts.get("SUSPICIOUS", 0)
        high = risk_counts.get("HIGH", 0)

        activity_data = get_scan_activity()
        recent = get_all_scans(page=1, per_page=5, sort_by="scan_timestamp", order="desc")

        return jsonify({
            "success": True,
            "data": {
                "total_scans": total,
                "low_risk": low,
                "suspicious": suspicious,
                "high_risk": high,
                "risk_distribution": {
                    "LOW": low,
                    "SUSPICIOUS": suspicious,
                    "HIGH": high,
                },
                "scan_activity": activity_data,
                "recent_scans": recent["scans"],
            },
        })
    except Exception:
        return jsonify({
            "success": False,
            "error": "An internal error occurred while loading dashboard.",
        }), 500
