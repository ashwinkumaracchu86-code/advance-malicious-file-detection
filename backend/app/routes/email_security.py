import json
import uuid
import logging
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
from ..security.auth import get_current_user, verify_token
from ..security.encryption import encrypt_value, decrypt_value
from ..services.email_monitor_service import (
    parse_eml_content, analyze_sender, analyze_subject, analyze_body,
    analyze_attachment, get_auth_results, test_connection,
    email_monitor,
)
from ..services.url_scanner import extract_and_analyze_urls, get_url_summary
from ..services.email_risk_engine import calculate_email_risk_score

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/email-security", tags=["Email Security"])


class MonitoringConfigRequest(BaseModel):
    provider: str = "imap"
    imap_host: str
    imap_port: int = 993
    use_ssl: bool = True
    username: str
    password: str = ""
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

    attachment_analyses = [analyze_attachment(att, 25) for att in parsed["attachments"]]
    risk_result = calculate_email_risk_score(
        sender_analysis=sender_result, subject_analysis=subject_result,
        body_analysis=body_result, url_analyses=url_analyses,
        attachment_analyses=attachment_analyses,
    )

    auth_results = get_auth_results(parsed["headers"])
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
        spf=auth_results.get("spf"), dkim=auth_results.get("dkim"),
        dmarc=auth_results.get("dmarc"), scan_source="upload",
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
            detected_mime=att_analysis.get("detected_mime", ""),
            entropy=att_analysis.get("entropy", 0.0),
            risk_score=att_analysis.get("risk_score", 0), classification=att_analysis.get("classification", "safe"),
            is_dangerous_extension=att_analysis.get("is_dangerous_extension", False),
            is_double_extension=att_analysis.get("is_double_extension", False),
            is_mime_mismatch=att_analysis.get("is_mime_mismatch", False),
            clamav_result=att_analysis.get("clamav_result"),
            clamav_virus_name=att_analysis.get("clamav_virus_name"),
            detection_reasons=json.dumps(att_analysis.get("detection_reasons") or att_analysis.get("reasons") or [], default=str),
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
    recipient: Optional[str] = None, message_id: Optional[str] = None,
    search: Optional[str] = None, spf: Optional[str] = None,
    dkim: Optional[str] = None, dmarc: Optional[str] = None,
    is_quarantined: Optional[bool] = None, has_attachments: Optional[bool] = None,
    min_risk: Optional[float] = None, max_risk: Optional[float] = None,
    date_from: Optional[str] = None, date_to: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    query = db.query(EmailRecord).filter(EmailRecord.user_id == current_user.id)
    if classification:
        query = query.filter(EmailRecord.classification == classification)
    if sender:
        query = query.filter(EmailRecord.sender.contains(sender))
    if recipient:
        query = query.filter(EmailRecord.recipient.contains(recipient))
    if message_id:
        query = query.filter(EmailRecord.message_id.contains(message_id))
    if spf:
        query = query.filter(EmailRecord.spf == spf.upper())
    if dkim:
        query = query.filter(EmailRecord.dkim == dkim.upper())
    if dmarc:
        query = query.filter(EmailRecord.dmarc == dmarc.upper())
    if is_quarantined is not None:
        query = query.filter(EmailRecord.is_quarantined == is_quarantined)
    if has_attachments is not None:
        if has_attachments:
            query = query.filter(EmailRecord.total_attachments > 0)
        else:
            query = query.filter(EmailRecord.total_attachments == 0)
    if min_risk is not None:
        query = query.filter(EmailRecord.risk_score >= min_risk)
    if max_risk is not None:
        query = query.filter(EmailRecord.risk_score <= max_risk)
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            query = query.filter(EmailRecord.scan_date >= dt)
        except ValueError:
            pass
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            query = query.filter(EmailRecord.scan_date <= dt)
        except ValueError:
            pass
    if search:
        query = query.filter(
            (EmailRecord.subject.contains(search)) |
            (EmailRecord.sender.contains(search)) |
            (EmailRecord.recipient.contains(search)) |
            (EmailRecord.message_id.contains(search)) |
            (EmailRecord.id.in_(
                db.query(EmailAttachment.email_id).filter(
                    (EmailAttachment.filename.contains(search)) |
                    (EmailAttachment.sha256.contains(search))).subquery()
            )))
    total = query.count()
    emails = query.order_by(desc(EmailRecord.scan_date)).offset(skip).limit(limit).all()
    return {"total": total, "skip": skip, "limit": limit,
        "emails": [{"id": e.id, "sender": e.sender, "sender_domain": e.sender_domain,
            "recipient": e.recipient, "subject": e.subject, "risk_score": e.risk_score,
            "classification": e.classification, "is_quarantined": e.is_quarantined,
            "total_attachments": e.total_attachments, "threat_count": e.threat_count,
            "url_count": e.url_count,
            "spf": e.spf, "dkim": e.dkim, "dmarc": e.dmarc,
            "message_id": e.message_id,
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
            "subject": email_record.subject, "message_id": email_record.message_id,
            "reply_to": email_record.reply_to, "return_path": email_record.return_path,
            "scan_source": email_record.scan_source,
            "spf": email_record.spf, "dkim": email_record.dkim, "dmarc": email_record.dmarc,
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
            "extension": a.extension, "detected_mime": a.detected_mime, "entropy": a.entropy,
            "risk_score": a.risk_score, "classification": a.classification,
            "is_dangerous_extension": a.is_dangerous_extension, "is_double_extension": a.is_double_extension,
            "is_mime_mismatch": a.is_mime_mismatch, "is_quarantined": a.is_quarantined,
            "quarantine_path": a.quarantine_path,
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


@router.post("/emails/{email_id}/quarantine")
def quarantine_email_record(
    email_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    """Quarantine a scanned email by its EmailRecord id (creates/updates the quarantine row)."""
    email_record = db.query(EmailRecord).filter(
        EmailRecord.id == email_id, EmailRecord.user_id == current_user.id).first()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")
    existing = db.query(EmailQuarantine).filter(
        EmailQuarantine.email_id == email_id,
        EmailQuarantine.user_id == current_user.id).first()
    if not existing:
        existing = EmailQuarantine(
            email_id=email_record.id, user_id=current_user.id,
            risk_score=email_record.risk_score,
            classification=email_record.classification,
            reason="Manually quarantined by administrator",
            status="quarantined",
        )
        db.add(existing)
    else:
        existing.status = "quarantined"
    email_record.is_quarantined = True
    db.add(AuditLog(user_id=current_user.id, action="email_quarantine_manual",
        details=f"Manually quarantined email {email_id}", result="success"))
    db.commit()
    return {"status": "success", "action": "quarantine", "email_id": email_id}


@router.post("/emails/{email_id}/release")
def release_email_record(
    email_id: int, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    """Release a quarantined email by its EmailRecord id."""
    email_record = db.query(EmailRecord).filter(
        EmailRecord.id == email_id, EmailRecord.user_id == current_user.id).first()
    if not email_record:
        raise HTTPException(status_code=404, detail="Email not found")
    email_record.is_quarantined = False
    existing = db.query(EmailQuarantine).filter(
        EmailQuarantine.email_id == email_id,
        EmailQuarantine.user_id == current_user.id).first()
    if existing:
        existing.status = "released"
    db.add(AuditLog(user_id=current_user.id, action="email_quarantine_released",
        details=f"Released email {email_id}", result="success"))
    db.commit()
    return {"status": "success", "action": "release", "email_id": email_id}


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
        "last_check": config.last_check.isoformat() if config.last_check else None,
        "last_success_check": config.last_success_check.isoformat() if config.last_success_check else None,
        "last_error": config.last_error,
        "connection_status": config.connection_status or "unknown",
        "last_heartbeat": config.last_heartbeat.isoformat() if config.last_heartbeat else None,
        "emails_checked": config.emails_checked or 0,
        "threats_detected": config.threats_detected or 0,
        "quarantined_attachments": config.quarantined_attachments or 0}


@router.post("/monitoring/config")
def save_monitoring_config(config_req: MonitoringConfigRequest, db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    if config_req.password and not config_req.password.startswith("enc:"):
        encrypted = encrypt_value(config_req.password)
    else:
        encrypted = config_req.password
    existing = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if existing:
        for attr in ["provider", "imap_host", "imap_port", "use_ssl", "username",
                      "polling_interval_seconds", "max_attachment_size_mb", "auto_quarantine_threshold"]:
            setattr(existing, attr, getattr(config_req, attr))
        if encrypted:
            existing.password_encrypted = encrypted
        existing.folders_to_monitor = json.dumps(config_req.folders_to_monitor)
        config_record = existing
    else:
        config_record = EmailMonitoringConfig(
            user_id=current_user.id, provider=config_req.provider,
            imap_host=config_req.imap_host, imap_port=config_req.imap_port,
            use_ssl=config_req.use_ssl, username=config_req.username,
            password_encrypted=encrypted,
            polling_interval_seconds=config_req.polling_interval_seconds,
            folders_to_monitor=json.dumps(config_req.folders_to_monitor),
            max_attachment_size_mb=config_req.max_attachment_size_mb,
            auto_quarantine_threshold=config_req.auto_quarantine_threshold)
        db.add(config_record)
    db.commit()
    # Update in-memory worker state WITHOUT passing a plaintext password.
    email_monitor.update_config(config_record.id, {
        "is_active": config_record.is_active, "imap_host": config_req.imap_host,
        "imap_port": config_req.imap_port, "use_ssl": config_req.use_ssl,
        "username": config_req.username,
        "folders_to_monitor": json.dumps(config_req.folders_to_monitor),
        "polling_interval_seconds": config_req.polling_interval_seconds,
        "max_attachment_size_mb": config_req.max_attachment_size_mb,
        "auto_quarantine_threshold": config_req.auto_quarantine_threshold,
        "last_uid": config_record.last_uid or 0})
    return {"status": "success", "message": "Monitoring configuration saved"}


@router.post("/monitoring/test-connection")
def test_connection_endpoint(config_req: Optional[MonitoringConfigRequest] = None,
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Perform a REAL IMAP connection test.

    Uses the saved configuration unless an explicit config is provided.
    Never returns the password.
    """
    if config_req is None:
        config = db.query(EmailMonitoringConfig).filter(
            EmailMonitoringConfig.user_id == current_user.id).first()
        if not config:
            return {"status": "NOT_CONFIGURED", "message": "No monitoring configuration found"}
        imap_host = config.imap_host
        imap_port = config.imap_port
        use_ssl = config.use_ssl
        username = config.username
        password = decrypt_value(config.password_encrypted or "")
        folders = json.loads(config.folders_to_monitor) if config.folders_to_monitor else ["INBOX"]
    else:
        imap_host = config_req.imap_host
        imap_port = config_req.imap_port
        use_ssl = config_req.use_ssl
        username = config_req.username
        password = config_req.password
        folders = config_req.folders_to_monitor or ["INBOX"]

    result = test_connection(imap_host, imap_port, use_ssl, username, password, folders)
    label = "CONNECTED" if result.get("status") == "connected" else "FAILED"
    return {**result, "status": label}


@router.post("/monitoring/start")
def start_monitoring(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    config = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    if not config:
        raise HTTPException(status_code=400, detail="No monitoring configuration found")
    if not config.imap_host or not config.username or not config.password_encrypted:
        raise HTTPException(status_code=400, detail="Monitoring configuration is incomplete (host, username or password required)")
    config.is_active = True
    db.commit()
    # Load config into the in-memory worker WITHOUT transferring a clear password.
    email_monitor.update_config(config.id, {
        "is_active": True, "imap_host": config.imap_host, "imap_port": config.imap_port,
        "use_ssl": config.use_ssl, "username": config.username,
        "password": config.password_encrypted,
        "folders_to_monitor": config.folders_to_monitor, "last_uid": config.last_uid or 0,
        "polling_interval_seconds": config.polling_interval_seconds,
        "max_attachment_size_mb": config.max_attachment_size_mb,
        "auto_quarantine_threshold": config.auto_quarantine_threshold})
    email_monitor.start()
    db.add(AuditLog(user_id=current_user.id, action="email_monitoring_started",
        details=f"Started monitoring for {config.username}@{config.imap_host}", result="success"))
    db.commit()
    return {"status": "success", "message": "Email monitoring started",
        "monitoring_status": "active", "worker_running": email_monitor.is_running()}


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
    return {"status": "success", "message": "Email monitoring stopped",
        "monitoring_status": "stopped", "worker_running": email_monitor.is_running()}


@router.get("/monitoring/status")
def get_monitoring_status(db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)):
    """Return real monitoring state backed by the worker + persisted heartbeat."""
    from datetime import timedelta
    config = db.query(EmailMonitoringConfig).filter(
        EmailMonitoringConfig.user_id == current_user.id).first()
    base = {
        "monitor_running": email_monitor.is_running(),
        "active_configs": len(email_monitor._configs),
        "configured": config is not None,
    }
    if not config:
        base.update({
            "monitoring_status": "NOT_CONFIGURED",
            "connection_status": "unknown",
            "worker_running": False,
            "last_check": None, "last_successful_check": None,
            "last_error": None, "heartbeat_stale": True,
            "polling_interval_seconds": None,
            "emails_checked": 0, "threats_detected": 0, "quarantined_attachments": 0,
        })
        return base

    worker_running = email_monitor.is_running()
    configured_active = bool(config.is_active)
    connection_status = (config.connection_status or "unknown").lower()

    # heartbeat staleness
    penalty = 5 * max(10, int(config.polling_interval_seconds or 60))
    last_hb = config.last_heartbeat
    heartbeat_stale = True
    if last_hb is not None:
        try:
            heartbeat_stale = (datetime.now(timezone.utc) - last_hb).total_seconds() > penalty
        except Exception:
            heartbeat_stale = True

    if connection_status == "connected" and worker_running and not heartbeat_stale:
        monitoring_status = "active"
    elif config.is_active and worker_running:
        monitoring_status = "starting"
    elif config.is_active:
        monitoring_status = "error" if connection_status == "error" else "starting"
    else:
        monitoring_status = "stopped"

    base.update({
        "monitoring_status": monitoring_status,
        "connection_status": connection_status,
        "worker_running": worker_running,
        "is_active": configured_active,
        "last_check": config.last_check.isoformat() if config.last_check else None,
        "last_successful_check": config.last_success_check.isoformat() if config.last_success_check else None,
        "last_error": config.last_error,
        "last_heartbeat": config.last_heartbeat.isoformat() if config.last_heartbeat else None,
        "heartbeat_stale": heartbeat_stale,
        "polling_interval_seconds": config.polling_interval_seconds,
        "username": config.username,
        "emails_checked": config.emails_checked or 0,
        "threats_detected": config.threats_detected or 0,
        "quarantined_attachments": config.quarantined_attachments or 0,
    })
    return base


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str = Query(None)):
    """WebSocket endpoint for real-time email security events with token authentication."""
    if not token:
        await websocket.close(code=4001, reason="Authentication token required")
        return
    payload = verify_token(token, token_type="access")
    if not payload:
        await websocket.close(code=4003, reason="Invalid or expired token")
        return
    await websocket.accept()
    email_monitor.register_ws(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        email_monitor.unregister_ws(websocket)
    except Exception:
        email_monitor.unregister_ws(websocket)
