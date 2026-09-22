from io import BytesIO
from flask import Blueprint, jsonify, send_file, Response
from database import get_scan
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

report_bp = Blueprint("report", __name__)

RISK_COLORS = {
    "LOW": "#10b981",
    "SUSPICIOUS": "#f59e0b",
    "HIGH": "#ef4444",
}

def _build_report_data(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return None
    metadata = scan.get("metadata", {}) if isinstance(scan.get("metadata"), dict) else {}
    indicators = scan.get("indicators", []) if isinstance(scan.get("indicators"), list) else []
    return {
        "report_id": "RPT-{:06d}".format(scan["id"]),
        "scan_id": scan["id"],
        "filename": scan["filename"],
        "extension": scan["extension"],
        "file_type": scan["file_type"],
        "mime_type": scan["mime_type"],
        "file_size": scan["file_size"],
        "md5": scan["md5"],
        "sha256": scan["sha256"],
        "risk_score": scan["risk_score"],
        "risk_level": scan["risk_level"],
        "indicators": indicators,
        "metadata": metadata,
        "explanation": metadata.get("explanation", "No explanation available."),
        "scan_timestamp": scan["scan_timestamp"],
    }
@report_bp.route("/api/reports/<int:scan_id>", methods=["GET"])
def get_report(scan_id):
    try:
        report = _build_report_data(scan_id)
        if not report:
            return jsonify({"success": False, "error": "Report for scan {} not found.".format(scan_id)}), 404
        return jsonify({"success": True, "data": report})
    except Exception:
        return jsonify({"success": False, "error": "An internal error occurred while generating the report."}), 500


def _format_bytes(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return "{:.1f} {}".format(size, unit)
        size /= 1024
    return "{:.1f} TB".format(size)


def _risk_color(level):
    return HexColor(RISK_COLORS.get(level, "#64748b"))


def _generate_pdf_bytes(report):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=0.75*inch, rightMargin=0.75*inch, topMargin=0.6*inch, bottomMargin=0.6*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, textColor=HexColor("#0e7490"), spaceAfter=6)
    heading_style = ParagraphStyle("Heading2", parent=styles["Heading2"], fontSize=13, textColor=HexColor("#1e293b"), spaceBefore=12, spaceAfter=6)
    body_style = styles["BodyText"]
    subtitle_style = ParagraphStyle("Subtitle2", parent=styles["Normal"], fontSize=12, textColor=HexColor("#64748b"), spaceAfter=10)
    small_style = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, textColor=HexColor("#64748b"))

    elements = []
    elements.append(Paragraph("Malicious File Detection System", title_style))
    elements.append(Paragraph("Security Analysis Report", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", color=HexColor("#e2e8f0"), thickness=1))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Scan Information", heading_style))
    info_data = [
        ["Report ID", report["report_id"]],
        ["Scan ID", str(report["scan_id"])],
        ["Scan Date", str(report["scan_timestamp"])],
        ["Application", "Malicious File Detection System"],
    ]
    t = Table(info_data, colWidths=[1.5*inch, 5*inch])
    t.setStyle(TableStyle([("FONTSIZE", (0,0), (-1,-1), 10), ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4), ("TEXTCOLOR", (0,0), (0,-1), HexColor("#64748b"))]))
    elements.append(t)
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("Risk Assessment", heading_style))
    risk_data = [["Risk Score", "{}/100".format(report["risk_score"])], ["Risk Level", report["risk_level"]]]
    t2 = Table(risk_data, colWidths=[1.5*inch, 5*inch])
    t2.setStyle(TableStyle([("FONTSIZE", (0,0), (-1,-1), 10), ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4), ("TEXTCOLOR", (0,0), (0,-1), HexColor("#64748b")), ("TEXTCOLOR", (1,1), (1,1), _risk_color(report["risk_level"])), ("FONTNAME", (1,1), (1,1), "Helvetica-Bold")]))
    elements.append(t2)
    elements.append(Spacer(1, 6))

    elements.append(Paragraph("File Information", heading_style))
    file_data = [
        ["Filename", report["filename"]],
        ["File Type", report["file_type"]],
        ["MIME Type", report["mime_type"]],
        ["Extension", report["extension"] or "None"],
        ["File Size", _format_bytes(report["file_size"])],
    ]
    t3 = Table(file_data, colWidths=[1.5*inch, 5*inch])
    t3.setStyle(TableStyle([("FONTSIZE", (0,0), (-1,-1), 10), ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4), ("TEXTCOLOR", (0,0), (0,-1), HexColor("#64748b"))]))
    elements.append(t3)
    elements.append(Spacer(1, 6))

    elements.append(Paragraph("Cryptographic Hashes", heading_style))
    hash_data = [["MD5", report["md5"]], ["SHA-256", report["sha256"]]]
    t4 = Table(hash_data, colWidths=[1.5*inch, 5*inch])
    t4.setStyle(TableStyle([("FONTSIZE", (0,0), (-1,-1), 8), ("FONTNAME", (1,0), (1,-1), "Courier"), ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4), ("TEXTCOLOR", (0,0), (0,-1), HexColor("#64748b"))]))
    elements.append(t4)
    elements.append(Spacer(1, 6))

    if report["indicators"]:
        elements.append(Paragraph("Detected Indicators", heading_style))
        ind_header = [["#", "Indicator", "Severity", "Points"]]
        ind_rows = []
        for i, ind in enumerate(report["indicators"], 1):
            ind_rows.append([str(i), ind.get("name", "Unknown"), ind.get("severity", "info").upper(), "+{}".format(ind.get("points", 0))])
        ind_table = Table(ind_header + ind_rows, colWidths=[0.4*inch, 3.5*inch, 1.2*inch, 0.8*inch])
        ind_table.setStyle(TableStyle([
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("BACKGROUND", (0,0), (-1,0), HexColor("#f1f5f9")),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("GRID", (0,0), (-1,-1), 0.5, HexColor("#e2e8f0")),
        ]))
        elements.append(ind_table)
    else:
        elements.append(Paragraph("Detected Indicators", heading_style))
        elements.append(Paragraph("No indicators triggered. This is a clean file.", body_style))
    elements.append(Spacer(1, 6))

    elements.append(Paragraph("Score Breakdown", heading_style))
    expl_text = report["explanation"].replace("\n", "<br/>")
    elements.append(Paragraph(expl_text, ParagraphStyle("Explanation", parent=body_style, fontSize=9, backColor=HexColor("#f8fafc"), borderWidth=0.5, borderColor=HexColor("#e2e8f0"), borderPadding=8)))
    elements.append(Spacer(1, 6))

    elements.append(Paragraph("Security Recommendation", heading_style))
    if report["risk_score"] > 70:
        rec = "HIGH RISK: Do not open or execute this file. Submit for manual review by a security analyst."
    elif report["risk_score"] > 30:
        rec = "SUSPICIOUS: Exercise caution. Verify the file source and scan with a trusted antivirus solution before use."
    else:
        rec = "LOW RISK: No significant risk indicators detected. This does not guarantee the file is safe."
    elements.append(Paragraph(rec, body_style))
    elements.append(Spacer(1, 12))

    elements.append(HRFlowable(width="100%", color=HexColor("#e2e8f0"), thickness=1))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph("Disclaimer: This report is generated by automated static analysis. It does not guarantee the file is safe or malicious. Always use multiple security tools and manual review for critical decisions.", small_style))
    elements.append(Paragraph("Generated by Malicious File Detection System", small_style))

    doc.build(elements)
    buf.seek(0)
    return buf


@report_bp.route("/api/reports/<int:scan_id>/pdf", methods=["GET"])
def get_report_pdf(scan_id):
    try:
        report = _build_report_data(scan_id)
        if not report:
            return jsonify({"success": False, "error": "Report for scan {} not found.".format(scan_id)}), 404
        pdf_buf = _generate_pdf_bytes(report)
        filename = "report_{}.pdf".format(report["report_id"])
        return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception:
        return jsonify({"success": False, "error": "An internal error occurred while generating the PDF report."}), 500


@report_bp.route("/api/reports/<int:scan_id>/html", methods=["GET"])
def get_report_html(scan_id):
    try:
        report = _build_report_data(scan_id)
        if not report:
            return jsonify({"success": False, "error": "Report for scan {} not found.".format(scan_id)}), 404

        risk_color = RISK_COLORS.get(report["risk_level"], "#64748b")
        indicators_rows = ""
        if report["indicators"]:
            for i, ind in enumerate(report["indicators"], 1):
                sev = ind.get("severity", "info")
                sev_color = "#ef4444" if sev == "critical" else "#f59e0b" if sev == "warning" else "#64748b"
                indicators_rows += "<tr><td>{}</td><td>{}</td><td style=color:{}>{}</td><td>+{}</td></tr>".format(i, ind.get("name","Unknown"), sev_color, sev.upper(), ind.get("points",0))
            indicators_html = "<table><thead><tr><th>#</th><th>Indicator</th><th>Severity</th><th>Points</th></tr></thead><tbody>{}</tbody></table>".format(indicators_rows)
        else:
            indicators_html = "<p style=color:#10b981;font-style:italic>No indicators triggered. This is a clean file.</p>"

        if report["risk_score"] > 70:
            rec = "HIGH RISK: Do not open or execute this file. Submit for manual review by a security analyst."
        elif report["risk_score"] > 30:
            rec = "SUSPICIOUS: Exercise caution. Verify the file source before use."
        else:
            rec = "LOW RISK: No significant risk indicators detected."

        explanation = report["explanation"].replace("\n", "<br/>")
        fmt = _format_bytes(report["file_size"])
        rep_id = report["report_id"]
        scan_id_str = str(report["scan_id"])
        scan_date = str(report["scan_timestamp"])
        fname = report["filename"]
        ftype = report["file_type"]
        mime = report["mime_type"]
        ext = report["extension"] or "None"
        score = str(report["risk_score"])
        level = report["risk_level"]
        md5_val = report["md5"]
        sha_val = report["sha256"]

        css = ("*{margin:0;padding:0;box-sizing:border-box}"
            "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#f8fafc;color:#1e293b;line-height:1.6}"
            ".container{max-width:800px;margin:0 auto;padding:24px}"
            ".header{text-align:center;margin-bottom:24px;padding:24px;background:white;border-radius:12px;border:1px solid #e2e8f0}"
            ".header h1{color:#0e7490;font-size:22px;margin-bottom:4px}"
            ".header p{color:#64748b;font-size:14px}"
            ".risk-banner{text-align:center;padding:16px;border-radius:8px;margin-bottom:24px;color:white;font-weight:600;font-size:18px}"
            ".section{background:white;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin-bottom:16px}"
            ".section h2{font-size:16px;color:#0e7490;margin-bottom:12px;border-bottom:1px solid #e2e8f0;padding-bottom:8px}"
            ".info-grid{display:grid;grid-template-columns:160px 1fr;gap:8px;font-size:14px}"
            ".info-grid dt{color:#64748b}.info-grid dd{font-weight:500}"
            ".hash{font-family:Courier New,monospace;font-size:12px;word-break:break-all;background:#f1f5f9;padding:8px;border-radius:4px;margin:4px 0}"
            "table{width:100%;border-collapse:collapse;font-size:14px}"
            "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #e2e8f0}"
            "th{background:#f1f5f9;font-weight:600;font-size:12px;text-transform:uppercase;color:#64748b}"
            ".explanation{background:#f8fafc;padding:12px;border-radius:4px;font-size:13px;border:1px solid #e2e8f0;white-space:pre-wrap}"
            ".recommendation{padding:12px;border-radius:4px;font-size:14px}"
            ".disclaimer{text-align:center;color:#94a3b8;font-size:11px;margin-top:24px;padding-top:16px;border-top:1px solid #e2e8f0}"
            "@media print{body{background:white}.container{padding:0}}")

        html = []
        html.append("<!DOCTYPE html><html lang=en><head><meta charset=UTF-8><meta name=viewport content=device-width,initial-scale=1.0>")
        html.append("<title>Report {} - Malicious File Detection System</title>".format(rep_id))
        html.append("<style>{}</style></head><body>".format(css))
        html.append("<div class=container>")
        html.append("<div class=header><h1>Malicious File Detection System</h1><p>Security Analysis Report &mdash; {}</p></div>".format(rep_id))
        html.append("<div class=risk-banner style=background:{}>Risk Score: {} / 100 &mdash; {}</div>".format(risk_color, score, level))
        html.append("<div class=section><h2>Scan Information</h2><dl class=info-grid><dt>Report ID</dt><dd>{}</dd><dt>Scan ID</dt><dd>{}</dd><dt>Scan Date</dt><dd>{}</dd><dt>Application</dt><dd>Malicious File Detection System</dd></dl></div>".format(rep_id, scan_id_str, scan_date))
        html.append("<div class=section><h2>File Information</h2><dl class=info-grid><dt>Filename</dt><dd>{}</dd><dt>File Type</dt><dd>{}</dd><dt>MIME Type</dt><dd>{}</dd><dt>Extension</dt><dd>{}</dd><dt>File Size</dt><dd>{}</dd></dl></div>".format(fname, ftype, mime, ext, fmt))
        html.append("<div class=section><h2>Cryptographic Hashes</h2><dt style=color:#64748b;font-size:13px>MD5</dt><div class=hash>{}</div><dt style=color:#64748b;font-size:13px>SHA-256</dt><div class=hash>{}</div></div>".format(md5_val, sha_val))
        html.append("<div class=section><h2>Detected Indicators</h2>{}</div>".format(indicators_html))
        html.append("<div class=section><h2>Score Breakdown</h2><div class=explanation>{}</div></div>".format(explanation))
        html.append("<div class=section><h2>Security Recommendation</h2><div class=recommendation>{}</div></div>".format(rec))
        html.append("<div class=disclaimer><p>This report is generated by automated static analysis. It does not guarantee the file is safe or malicious.</p><p>Generated by Malicious File Detection System</p></div>")
        html.append("</div></body></html>")

        return Response("".join(html), mimetype="text/html")
    except Exception:
        return jsonify({"success": False, "error": "An internal error occurred while generating the HTML report."}), 500
