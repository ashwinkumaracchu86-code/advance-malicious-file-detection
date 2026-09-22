import os
import json
import uuid
import logging
import tempfile
import hashlib
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from pydantic import BaseModel
from ..database import get_db
from ..models.models import User, AuditLog
from ..models.email_models import (
    EmailRecord, EmailHeader, EmailAttachment, EmailUrlAnalysis,
    EmailDetection, EmailAlert, EmailQuarantine, EmailScanEvent,
    EmailMonitoringConfig,
)
from ..security.auth import get_current_user
from ..services.email_monitor_service import (
    parse_eml_content, analyze_sender, analyze_subject, analyze_body,
    email_monitor,
)
from ..services.url_scanner import extract_and_analyze_urls, get_url_summary
from ..services.archive_analyzer import analyze_archive
from ..services.email_risk_engine import calculate_email_risk_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/email-security", tags=["Email Security"])


class MonitoringConfigRequest(BaseModel):
    provider: str = "imap"
    imap_host: str
    imap_port: int = 993
    use_ssl: bool = True
    username: str
    password: str
    polling_interval_seconds: int = 60
    folders_to_monitor: List[str] = ["INBOX"]
    max_attachment_size_mb: int = 25
    auto_quarantine_threshold: float = 70.0


class EmailQuarantineAction(BaseModel):
    action: str
    reason: Optional[str] = None


DANGEROUS_EXT = {
    '.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.vbs', '.vbe', '.js',
    '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.pif', '.hta', '.cpl',
    '.docm', '.xlsm', '.pptm', '.dotm',
}


def _store_event(db, email_id, event_type, data, source="system"):
    db.add(EmailScanEvent(
        email_id=email_id, event_type=event_type,
        event_data=json.dumps(data, default=str), source=source,
    ))


def _create_alert(db, email_id, user_id, alert_type, severity, title, message):
    db.add(EmailAlert(
        email_id=email_id, user_id=user_id, alert_type=alert_type,
        severity=severity, title=title, message=message,
    ))


def _analyze_attachment(att):
    data = att.get("data", b"")
    filename = att.get("filename", "unnamed")
    ext = os.path.splitext(filename)[1].lower()
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    reasons = []
    score = 0.0

    if ext in DANGEROUS_EXT:
        reasons.append(f"Dangerous extension: {ext}")
        score += 30

    parts = filename.split('.')
    if len(parts) > 2:
        reasons.append(f"Double extension: {filename}")
        score += 25

    if ext in ('.zip', '.tar', '.tgz', '.rar', '.7z'):
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            archive_result = analyze_archive(tmp_path)
            if archive_result.get("threats_found", 0) > 0:
                reasons.append(f"Archive contains {archive_result['threats_found']} suspicious file(s)")
                score += archive_result.get("risk_score", 0) * 0.3
            if archive_result.get("is_password_protected"):
                reasons.append("Password-protected archive")
                score += 15
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    score = min(100.0, score)
    classification = "safe"
    if score >= 60:
        classification = "malicious"
    elif score >= 30:
        classification = "suspicious"
    elif score >= 15:
        classification = "low_risk"

    return {
        "filename": filename, "content_type": att.get("content_type", ""),
        "size": att.get("size", 0), "md5": md5, "sha1": sha1, "sha256": sha256,
        "extension": ext, "risk_score": round(score, 2), "classification": classification,
        "is_dangerous_extension": ext in DANGEROUS_EXT, "is_double_extension": len(parts) > 2,
        "detection_reasons": reasons, "reasons": reasons,
    }


@router.post("/scan")
async def scan_email_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    filename = file.filename or "unnamed.eml"
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Email file too large (max 50MB)")

    parsed = parse_eml_content(content)
    sender_result = analyze_sender(parsed["sender"], parsed["display_name"], parsed["headers"])
    subject_result = analyze_subject(parsed["subject"])
    body_result = analyze_body(parsed["body_text"], parsed["body_html"])
    url_analyses = extract_and_analyze_urls(parsed["body_text"], parsed["body_html"])
    url_summary = get_url_summary(url_analyses)

    attachment_analyses = [_analyze_attachment(att) for att in parsed["attachments"]]
    risk_result = calculate_email_risk_score(
        sender_analysis=sender_result, subject_analysis=subject_result,
        body_analysis=body_result, url_analyses=url_analyses,
        attachment_analyses=attachment_analyses,
    )

    should_quarantine = risk_result["risk_score"] >= 70.0
    email_record = EmailRecord(
        message_id=parsed["message_id"] or str(uuid.uuid4()),
        user_id=current_user.id, sender=parsed["sender"],
        sender_domain=sender_result.get("domain", ""),
        recipient=parsed["recipient"], subject=parsed["subject"],
        date_received=datetime.now(timezone.utc),
        body_text=parsed["body_text"][:5000], body_html=parsed["body_html"][:20000],
        raw_headers=json.dumps(parsed["headers"], default=str)[:10000],
        x_mailer=parsed["headers"].get("X-Mailer", ""),
        return_path=parsed["headers"].get("Return-Path", ""),
        reply_to=parsed["headers"].get("Reply-To", ""),
        risk_score=risk_result["risk_score"], classification=risk_result["classification"],
        is_quarantined=should_quarantine,
        total_attachments=len(attachment_analyses),
        threat_count=sum(1 for a in attachment_analyses if a.get("classification") in ("malicious", "suspicious")),
        url_count=url_summary["total_urls"],
    )
    db.add(email_record)
    db.flush()

    for h_name, h_value in parsed["headers"].items():
        db.add(EmailHeader(email_id=email_record.id, header_name=h_name, header_value=str(h_value)[:2000]))

    for att_analysis in attachment_analyses:
        db.add(EmailAttachment(
            email_id=email_record.id, filename=att_analysis.get("filename", ""),
            content_type=att_analysis.get("content_type", ""), file_size=att_analysis.get("size", 0),
            md5=att_analysis.get("md5", ""), sha1=att_analysis.get("sha1", ""),
            sha256=att_analysis.get("sha256", ""), extension=att_analysis.get("extension", ""),
            risk_score=att_analysis.get("risk_score", 0), classification=att_analysis.get("classification", "safe"),
            is_dangerous_extension=att_analysis.get("is_dangerous_extension", False),
            is_double_extension=att_analysis.get("is_double_extension", False),
            detection_reasons=json.dumps(att_analysis.get("reasons", []), default=str),
        ))

    for ua in url_analyses:
        db.add(EmailUrlAnalysis(
            email_id=email_record.id, url=ua.get("url", ""), domain=ua.get("domain", ""),
            is_https=ua.get("is_https", False), is_ip_url=ua.get("is_ip_url", False),
            is_shortened=ua.get("is_shortened", False), is_suspicious=ua.get("is_suspicious", False),
            is_phishing=ua.get("is_phishing", False), risk_score=ua.get("risk_score", 0),
            reputation=ua.get("reputation", "unknown"),
            detection_reasons=json.dumps(ua.get("reasons", []), default=str),
            found_in=ua.get("found_in", "body"),
        ))

    for reason in risk_result.get("reasons", []):
        db.add(EmailDetection(
            email_id=email_record.id, detection_type=reason.get("category", "general"),
            description=reason.get("description", ""),
            severity="critical" if reason.get("points", 0) >= 20 else ("high" if reason.get("points", 0) >= 10 else "medium"),
            category=reason.get("category", ""), points=reason.get("points", 0),
        ))

    if risk_result["classification"] in ("critical", "malicious"):
        _create_alert(db, email_record.id, current_user.id, "threat_detected",
            "critical" if risk_result["classification"] == "critical" else "high",
            f"{'CRITICAL' if risk_result['classification'] == 'critical' else 'Malicious'} Email Detected",
            f"Email from {parsed['sender']} - Score: {risk_result['risk_score']}/100")

    if should_quarantine:
        db.add(EmailQuarantine(
            email_id=email_record.id, user_id=current_user.id,
            risk_score=risk_result["risk_score"], classification=risk_result["classification"],
            reason=json.dumps([r.get("description", "") for r in risk_result.get("reasons", [])[:5]], default=str),
        ))

    _store_event(db, email_record.id, "scan_complete", {
        "risk_score": risk_result["risk_score"], "classification": risk_result["classification"],
        "attachments": len(attachment_analyses), "urls": url_summary["total_urls"],
    })

    db.add(AuditLog(user_id=current_user.id, action="email_scan",
        details=f"Scanned email from {parsed['sender']}. Score: {risk_result['risk_score']}", result="success"))
    db.commit()
    db.refresh(email_record)

    return {
        "email_id": email_record.id,
        "email": {"sender": parsed["sender"], "display_name": parsed["display_name"],
                  "recipient": parsed["recipient"], "subject": parsed["subject"],
                  "date": parsed["date"], "body_preview": parsed["body_text"][:500]},
        "sender_analysis": sender_result, "subject_analysis": subject_result,
        "body_analysis": {"reasons": body_result.get("reasons", []), "score": body_result.get("score", 0)},
        "url_analysis": {"summary": url_summary, "urls": url_analyses[:20]},
        "attachments": attachment_analyses, "risk_assessment": risk_result,
        "quarantined": should_quarantine, "scan_date": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/emails")
def list_emails(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
    classification: Optional[str] = None, sender: Optional[str] = None,
    search: Optional[str] = None, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    query = db.query(EmailRecord).filter(EmailRecord.user_id == current_user.id)
    if classification:
        query = query.filter(EmailRecord.classification == classification)
    if sender:
        query = query.filter(EmailRecord.sender.contains(sender))
    if search:
        query = query.filter((EmailRecord.subject.contains(search)) | (EmailRecord.sender.contains(search)))
    total = query.count()
    emails = query.order_by(desc(EmailRecord.scan_date)).offset(skip).limit(limit).all()
    return {"total": total, "skip": skip, "limit": limit,
        "emails": [{"id": e.id, "sender": e.sender, "sender_domain": e.sender_domain,
            "subject": e.subject, "risk_score": e.risk_score, "classification": e.classification,
            "is_quarantined": e.is_quarantined, "total_attachments": e.total_attachments,
            "threat_count": e.threat_count, "url_count": e.url_count,
            "scan_date": e.scan_date.isoformat() if e.scan_date else None} for e in emails]}


@router.get("/emails/{email_id}")
def get_email_detail(email_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    email_record = db.query(EmailRecord).filter(
        EmailRecord.id == email_id, EmailRecord.user_id == current_user.id).first()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")
    headers = db.query(EmailHeader).filter(EmailHeader.email_id == email_id).all()
    attachments = db.query(EmailAttachment).filter(EmailAttachment.email_id == email_id).all()
    url_analyses = db.query(EmailUrlAnalysis).filter(EmailUrlAnalysis.email_id == email_id).all()
    detections = db.query(EmailDetection).filter(EmailDetection.email_id == email_id).all()
    alerts = db.query(EmailAlert).filter(EmailAlert.email_id == email_id).all()
    return {
        "email": {"id": email_record.id, "sender": email_record.sender,
            "sender_domain": email_record.sender_domain, "recipient": email_record.recipient,
            "subject": email_record.subject,
            "date_received": email_record.date_received.isoformat() if email_record.date_received else None,
            "body_text": email_record.body_text, "body_html": email_record.body_html,
            "risk_score": email_record.risk_score, "classification": email_record.classification,
            "is_quarantined": email_record.is_quarantined,
            "total_attachments": email_record.total_attachments,
            "threat_count": email_record.threat_count, "url_count": email_record.url_count,
            "scan_date": email_record.scan_date.isoformat() if email_record.scan_date else None},
        "headers": [{"name": h.header_name, "value": h.header_value} for h in headers],
        "attachments": [{"id": a.id, "filename": a.filename, "content_type": a.content_type,
            "file_size": a.file_size, "md5": a.md5, "sha1": a.sha1, "sha256": a.sha256,
            "extension": a.extension, "risk_score": a.risk_score, "classification": a.classification,
            "is_dangerous_extension": a.is_dangerous_extension, "is_double_extension": a.is_double_extension,
            "detection_reasons": json.loads(a.detection_reasons) if a.detection_reasons else [],
            "clamav_result": a.clamav_result, "clamav_virus_name": a.clamav_virus_name} for a in attachments],
        "url_analyses": [{"url": u.url, "domain": u.domain, "is_https": u.is_https,
            "is_ip_url": u.is_ip_url, "is_shortened": u.is_shortened,
            "is_suspicious": u.is_suspicious, "is_phishing": u.is_phishing,
            "risk_score": u.risk_score, "reputation": u.reputation,
            "reasons": json.loads(u.detection_reasons) if u.detection_reasons else [],
            "found_in": u.found_in} for u in url_analyses],
        "detections": [{"type": d.detection_type, "rule_name": d.rule_name,
            "description": d.description, "severity": d.severity,
            "category": d.category, "points": d.points} for d in detections],
        "alerts": [{"id": a.id, "type": a.alert_type, "severity": a.severity,
            "title": a.title, "message": a.message, "is_read": a.is_read,
            "created_at": a.created_at.isoformat() if a.created_at else None} for a in alerts]}


@router.get("/stats")
def get_email_security_stats(days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from datetime import timedelta
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(EmailRecord).filter(EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since)
    total = q.count()
    malicious = q.filter(EmailRecord.classification == "malicious").count()
    critical = q.filter(EmailRecord.classification == "critical").count()
    suspicious = q.filter(EmailRecord.classification == "suspicious").count()
    safe = q.filter(EmailRecord.classification == "safe").count()
    quarantined = q.filter(EmailRecord.is_quarantined == True).count()
    total_attachments = db.query(func.sum(EmailRecord.total_attachments)).filter(
        EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since).scalar() or 0
    total_threats = db.query(func.sum(EmailRecord.threat_count)).filter(
        EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since).scalar() or 0
    avg_risk = db.query(func.avg(EmailRecord.risk_score)).filter(
        EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since).scalar() or 0
    daily_threats = db.query(func.date(EmailRecord.scan_date).label("date"),
        func.count(EmailRecord.id).label("count")).filter(
        EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since,
        EmailRecord.classification.in_(["malicious", "critical", "suspicious"])
    ).group_by(func.date(EmailRecord.scan_date)).all()
    top_senders = db.query(EmailRecord.sender_domain,
        func.count(EmailRecord.id).label("count")).filter(
        EmailRecord.user_id == current_user.id, EmailRecord.scan_date >= since,
        EmailRecord.classification.in_(["malicious", "critical", "suspicious"]),
        EmailRecord.sender_domain.isnot(None)
    ).group_by(EmailRecord.sender_domain).order_by(desc("count")).limit(10).all()
    return {"period_days": days, "total_scanned": total, "malicious": malicious,
        "critical": critical, "suspicious": suspicious, "safe": safe, "quarantined": quarantined,
        "total_attachments": total_attachments, "total_threats": total_threats,
        "average_risk_score": round(float(avg_risk), 2),
        "detection_rate": round((malicious + critical + suspicious) / total * 100, 2) if total > 0 else 0,
        "daily_threats": [{"date": str(d.date), "count": d.count} for d in daily_threats],
        "top_threat_senders": [{"domain": s.sender_domain, "count": s.count} for s in top_senders]}


@router.get("/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=200), unread_only: bool = False,
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(EmailAlert).filter(EmailAlert.user_id == current_user.id)
    if unread_only:
        query = query.filter(EmailAlert.is_read == False)
    alerts = query.order_by(desc(EmailAlert.created_at)).limit(limit).all()
    return {"alerts": [{"id": a.id, "email_id": a.email_id, "type": a.alert_type,
        "severity": a.severity, "title": a.title, "message": a.message,
        "is_read": a.is_read, "created_at": a.created_at.isoformat() if a.created_at else None} for a in alerts],
        "unread_count": db.query(EmailAlert).filter(
            EmailAlert.user_id == current_user.id, EmailAlert.is_read == False).count()}


@router.post("/alerts/{alert_id}/read")
def mark_alert_read(alert_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    alert = db.query(EmailAlert).filter(EmailAlert.id == alert_id,
        EmailAlert.user_id == current_user.id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    db.commit()
    return {"status": "success"}


@router.post("/alerts/read-all")
def mark_all_alerts_read(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    db.query(EmailAlert).filter(EmailAlert.user_id == current_user.id,
        EmailAlert.is_read == False).update({"is_read": True})
    db.commit()
    return {"status": "success"}


@router.get("/quarantine")
def list_quarantined_emails(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(EmailQuarantine).filter(EmailQuarantine.user_id == current_user.id)
    total = query.count()
    items = query.order_by(desc(EmailQuarantine.created_at)).offset(skip).limit(limit).all()
    results = []
    for item in items:
        er = db.query(EmailRecord).filter(EmailRecord.id == item.email_id).first()
        results.append({"id": item.id, "email_id": item.email_id,
            "sender": er.sender if er else "", "subject": er.subject if er else "",
            "risk_score": item.risk_score, "classification": item.classification,
            "reason": item.reason, "status": item.status,
            "created_at": item.created_at.isoformat() if item.created_at else None})
    return {"total": total, "quarantine": results}


@router.post("/quarantine/{item_id}/action")
def quarantine_action(item_id: int, action_req: EmailQuarantineAction,
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(EmailQuarantine).filter(EmailQuarantine.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Quarantine item not found")
    item.status = action_req.action
    item.reviewed_by = current_user.id
    item.reviewed_at = datetime.now(timezone.utc)
    item.action_taken = action_req.action
    if action_req.action == "release":
        er = db.query(EmailRecord).filter(EmailRecord.id == item.email_id).first()
        if er:
            er.is_quarantined = False
    elif action_req.action == "delete":
        er = db.query(EmailRecord).filter(EmailRecord.id == item.email_id).first()
        if er:
            db.delete(er)
    db.add(AuditLog(user_id=current_user.id, action=f"email_quarantine_{action_req.action}",
        details=f"Quarantine item {item_id}: {action_req.action}", result="success"))
    db.commit()
    return {"status": "success", "action": action_req.action}


@router.get("/events")
def get_scan_events(limit: int = Query(100, ge=1, le=500), event_type: Optional[str] = None,
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(EmailScanEvent)
    if event_type:
        query = query.filter(EmailScanEvent.event_type == event_type)
    events = query.order_by(desc(EmailScanEvent.timestamp)).limit(limit).all()
    return {"events": [{"id": e.id, "email_id": e.email_id, "event_type": e.event_type,
        "event_data": json.loads(e.event_data) if e.event_data else {},
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "source": e.source} for e in events]}


@router.get("/monitoring/config")
def get_monitoring_config(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    config = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if not config:
        return {"configured": False}
    return {"configured": True, "provider": config.provider, "imap_host": config.imap_host,
        "imap_port": config.imap_port, "use_ssl": config.use_ssl, "username": config.username,
        "polling_interval_seconds": config.polling_interval_seconds,
        "folders_to_monitor": json.loads(config.folders_to_monitor) if config.folders_to_monitor else ["INBOX"],
        "max_attachment_size_mb": config.max_attachment_size_mb,
        "auto_quarantine_threshold": config.auto_quarantine_threshold,
        "is_active": config.is_active,
        "last_check": config.last_check.isoformat() if config.last_check else None}


@router.post("/monitoring/config")
def save_monitoring_config(config_req: MonitoringConfigRequest, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    existing = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if existing:
        for attr in ["provider", "imap_host", "imap_port", "use_ssl", "username",
                      "polling_interval_seconds", "max_attachment_size_mb", "auto_quarantine_threshold"]:
            setattr(existing, attr, getattr(config_req, attr))
        if config_req.password:
            existing.password_encrypted = config_req.password
        existing.folders_to_monitor = json.dumps(config_req.folders_to_monitor)
        config_record = existing
    else:
        config_record = EmailMonitoringConfig(
            user_id=current_user.id, provider=config_req.provider,
            imap_host=config_req.imap_host, imap_port=config_req.imap_port,
            use_ssl=config_req.use_ssl, username=config_req.username,
            password_encrypted=config_req.password,
            polling_interval_seconds=config_req.polling_interval_seconds,
            folders_to_monitor=json.dumps(config_req.folders_to_monitor),
            max_attachment_size_mb=config_req.max_attachment_size_mb,
            auto_quarantine_threshold=config_req.auto_quarantine_threshold)
        db.add(config_record)
    db.commit()
    email_monitor.update_config(config_record.id, {
        "is_active": config_record.is_active, "imap_host": config_req.imap_host,
        "imap_port": config_req.imap_port, "use_ssl": config_req.use_ssl,
        "username": config_req.username, "password": config_req.password,
        "folders_to_monitor": json.dumps(config_req.folders_to_monitor),
        "last_uid": config_record.last_uid or 0})
    return {"status": "success", "message": "Monitoring configuration saved"}


@router.post("/monitoring/start")
def start_monitoring(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    config = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if not config:
        raise HTTPException(status_code=400, detail="No monitoring configuration found")
    config.is_active = True
    db.commit()
    email_monitor.update_config(config.id, {
        "is_active": True, "imap_host": config.imap_host, "imap_port": config.imap_port,
        "use_ssl": config.use_ssl, "username": config.username,
        "password": config.password_encrypted,
        "folders_to_monitor": config.folders_to_monitor, "last_uid": config.last_uid or 0})
    email_monitor.start()
    db.add(AuditLog(user_id=current_user.id, action="email_monitoring_started",
        details=f"Started monitoring for {config.username}@{config.imap_host}", result="success"))
    db.commit()
    return {"status": "success", "message": "Email monitoring started"}


@router.post("/monitoring/stop")
def stop_monitoring(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    config = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if config:
        config.is_active = False
        email_monitor.remove_config(config.id)
        db.commit()
    db.add(AuditLog(user_id=current_user.id, action="email_monitoring_stopped",
        details="Stopped email monitoring", result="success"))
    db.commit()
    return {"status": "success", "message": "Email monitoring stopped"}


@router.get("/monitoring/status")
def get_monitoring_status(current_user: User = Depends(get_current_user)):
    return {"monitor_running": email_monitor._running,
        "active_configs": len(email_monitor._configs)}


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    email_monitor.register_ws(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        email_monitor.unregister_ws(websocket)
    except Exception:
        email_monitor.unregister_ws(websocket)
