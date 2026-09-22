import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def calculate_email_risk_score(
    sender_analysis: Dict[str, Any],
    subject_analysis: Dict[str, Any],
    body_analysis: Dict[str, Any],
    url_analyses: List[Dict[str, Any]],
    attachment_analyses: List[Dict[str, Any]],
    header_analysis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    score = 0.0
    reasons = []

    sender_score = sender_analysis.get("score", 0)
    if sender_score > 0:
        score += sender_score * 0.30
        for r in sender_analysis.get("reasons", []):
            reasons.append({"category": "sender", "description": r, "points": 10})

    subject_score = subject_analysis.get("score", 0)
    if subject_score > 0:
        score += subject_score * 0.15
        for r in subject_analysis.get("reasons", []):
            reasons.append({"category": "subject", "description": r, "points": 8})

    body_score = body_analysis.get("score", 0)
    if body_score > 0:
        score += body_score * 0.15
        for r in body_analysis.get("reasons", []):
            reasons.append({"category": "body", "description": r, "points": 5})

    max_url_score = 0
    for ua in url_analyses:
        url_score = ua.get("risk_score", 0)
        max_url_score = max(max_url_score, url_score)
        if url_score > 0:
            score += url_score * 0.10
            for r in ua.get("reasons", []):
                reasons.append({"category": "url", "description": r, "points": 10})

    max_attachment_score = 0
    total_attachment_threats = 0
    for aa in attachment_analyses:
        att_score = aa.get("risk_score", 0)
        max_attachment_score = max(max_attachment_score, att_score)
        if att_score > 0:
            score += att_score * 0.25
            total_attachment_threats += 1
            for r in aa.get("detection_reasons", []) or aa.get("reasons", []):
                if isinstance(r, str):
                    reasons.append({"category": "attachment", "description": r, "points": 15})
                elif isinstance(r, dict):
                    reasons.append({"category": "attachment", "description": r.get("reason", str(r)), "points": 15})

    if header_analysis:
        header_score = header_analysis.get("score", 0)
        if header_score > 0:
            score += header_score * 0.05
            for r in header_analysis.get("reasons", []):
                reasons.append({"category": "header", "description": r, "points": 5})

    score = min(100.0, max(0.0, score))

    if score >= 80:
        classification = "critical"
        action = "block"
    elif score >= 60:
        classification = "malicious"
        action = "quarantine"
    elif score >= 30:
        classification = "suspicious"
        action = "review"
    elif score >= 15:
        classification = "low_risk"
        action = "allow_with_warning"
    else:
        classification = "safe"
        action = "allow"

    reasons.sort(key=lambda x: x.get("points", 0), reverse=True)

    return {
        "risk_score": round(score, 2),
        "classification": classification,
        "recommended_action": action,
        "reasons": reasons[:20],
        "total_indicators": len(reasons),
        "breakdown": {
            "sender_score": round(sender_score * 0.30, 2),
            "subject_score": round(subject_score * 0.15, 2),
            "body_score": round(body_score * 0.15, 2),
            "url_score": round(max_url_score * 0.10, 2),
            "attachment_score": round(max_attachment_score * 0.25, 2),
            "header_score": round((header_analysis.get("score", 0) if header_analysis else 0) * 0.05, 2),
        },
    }


def get_classification_color(classification: str) -> str:
    colors = {
        "safe": "#22c55e",
        "low_risk": "#3b82f6",
        "suspicious": "#eab308",
        "malicious": "#f97316",
        "critical": "#ef4444",
    }
    return colors.get(classification, "#6b7280")


def get_classification_label(classification: str) -> str:
    labels = {
        "safe": "Safe",
        "low_risk": "Low Risk",
        "suspicious": "Suspicious",
        "malicious": "Malicious",
        "critical": "Critical",
    }
    return labels.get(classification, "Unknown")


def get_action_label(action: str) -> str:
    labels = {
        "allow": "Allow",
        "allow_with_warning": "Allow with Warning",
        "review": "Review Required",
        "quarantine": "Quarantine",
        "block": "Block",
    }
    return labels.get(action, "Unknown")
