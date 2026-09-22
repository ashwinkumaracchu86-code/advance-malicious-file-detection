from flask import Blueprint, request, jsonify
from services.scan_service import process_upload, get_scan_detail, list_scans
from utils.file_security import (
    FileSecurityError,
    EmptyFileError,
    FileTooLargeError,
    BlockedFileError,
    PathTraversalError,
)

scan_routes_bp = Blueprint("scan_routes", __name__)


@scan_routes_bp.route("/api/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({
            "success": False,
            "error": "No file provided. Send a multipart form with a 'file' field.",
        }), 400

    file = request.files["file"]

    if not file.filename or not file.filename.strip():
        return jsonify({
            "success": False,
            "error": "Filename is empty.",
        }), 400

    try:
        result = process_upload(file)
        return jsonify({
            "success": True,
            "data": result["scan"],
            "explanation": result["explanation"],
        }), 201

    except EmptyFileError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except FileTooLargeError as e:
        return jsonify({"success": False, "error": str(e)}), 413
    except (BlockedFileError, PathTraversalError) as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except FileSecurityError as e:
        return jsonify({"success": False, "error": str(e)}), 422
    except Exception:
        return jsonify({
            "success": False,
            "error": "An internal error occurred during file analysis.",
        }), 500


@scan_routes_bp.route("/api/scans", methods=["GET"])
def get_scans():
    search = request.args.get("search", "").strip()
    risk = request.args.get("risk", "").strip().upper()
    sort = request.args.get("sort", "scan_timestamp").strip()
    order = request.args.get("order", "desc").strip().lower()
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 20, type=int)

    if page < 1:
        page = 1
    if limit < 1 or limit > 100:
        limit = 20

    if order not in ("asc", "desc"):
        order = "desc"

    allowed_sort_fields = {"scan_timestamp", "filename", "risk_score", "risk_level", "file_size", "id"}
    if sort not in allowed_sort_fields:
        sort = "scan_timestamp"

    if risk and risk not in ("LOW", "SUSPICIOUS", "HIGH"):
        return jsonify({
            "success": False,
            "error": "Invalid risk filter. Must be LOW, SUSPICIOUS, or HIGH.",
        }), 400

    try:
        result = list_scans(
            search=search,
            risk=risk,
            sort=sort,
            order=order,
            page=page,
            limit=limit,
        )
        return jsonify({
            "success": True,
            "data": result["scans"],
            "pagination": {
                "total": result["total"],
                "page": result["page"],
                "per_page": result["per_page"],
                "total_pages": result["total_pages"],
            },
        })
    except Exception:
        return jsonify({
            "success": False,
            "error": "An internal error occurred while retrieving scans.",
        }), 500


@scan_routes_bp.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan_by_id(scan_id: int):
    try:
        scan = get_scan_detail(scan_id)
        if not scan:
            return jsonify({
                "success": False,
                "error": f"Scan with id {scan_id} not found.",
            }), 404

        return jsonify({
            "success": True,
            "data": scan,
        })
    except Exception:
        return jsonify({
            "success": False,
            "error": "An internal error occurred while retrieving scan details.",
        }), 500
