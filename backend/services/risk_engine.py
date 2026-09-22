from analyzers.rule_engine import run_all_rules


RISK_THRESHOLDS = {
    "LOW": 30,
    "SUSPICIOUS": 70,
    "HIGH": 100,
}


def evaluate_risk(analysis: dict) -> dict:
    rule_results = run_all_rules(analysis)

    raw_score = 0
    triggered_rules = []

    for rule in rule_results:
        if rule.detected:
            raw_score += rule.points
            triggered_rules.append(rule)

    score = min(raw_score, 100)

    risk_level = _score_to_level(score)
    explanation = _build_explanation(score, risk_level, triggered_rules)

    indicators = [rule.to_dict() for rule in triggered_rules]

    return {
        "score": score,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
    }


def _score_to_level(score: int) -> str:
    if score <= RISK_THRESHOLDS["LOW"]:
        return "LOW"
    elif score <= RISK_THRESHOLDS["SUSPICIOUS"]:
        return "SUSPICIOUS"
    else:
        return "HIGH"


def _build_explanation(score: int, risk_level: str, triggered_rules) -> str:
    if not triggered_rules:
        return "No suspicious characteristics detected. Low-risk file."

    rule_descriptions = []
    for rule in triggered_rules:
        rule_descriptions.append(f"[{rule.severity.upper()}] {rule.name}: {rule.description}")

    level_messages = {
        "LOW": "Low-risk characteristics detected. This file shows minor indicators that warrant review.",
        "SUSPICIOUS": "Suspicious characteristics detected. This file exhibits patterns commonly associated with potentially unwanted software. Manual review recommended.",
        "HIGH": "High-risk characteristics detected. This file exhibits multiple indicators commonly associated with malicious or unwanted software. Strongly recommend manual review before use.",
    }

    parts = [level_messages.get(risk_level, "Analysis complete.")]
    parts.append(f"\nRisk Score: {score}/100 ({risk_level})")
    parts.append("\nTriggered Rules:")
    for desc in rule_descriptions:
        parts.append(f"  - {desc}")

    return "\n".join(parts)
