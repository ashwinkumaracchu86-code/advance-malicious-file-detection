import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from analyzers.rule_engine import run_all_rules
from services.risk_engine import evaluate_risk


def _make_analysis(**overrides) -> dict:
    base = {
        "filename": "test.txt",
        "extension": ".txt",
        "file_type": "text/plain",
        "mime_type": "text/plain",
        "file_size": 1024,
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "indicators": [],
        "metadata": {
            "original_filename": "test.txt",
            "extension": ".txt",
            "basename": "test",
            "file_size": 1024,
            "detected_type": "text",
            "detected_subtype": "plain",
        },
    }
    base.update(overrides)
    return base


def test_clean_text_file():
    print("=== Test 1: Clean Text File ===")
    analysis = _make_analysis()
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    print(f"  Indicators: {len(result['indicators'])}")
    assert result["score"] == 0, f"Expected 0, got {result['score']}"
    assert result["risk_level"] == "LOW", f"Expected LOW, got {result['risk_level']}"
    assert len(result["indicators"]) == 0
    print("  PASS\n")


def test_executable_extension():
    print("=== Test 2: Executable Extension ===")
    analysis = _make_analysis(
        filename="malware.exe",
        extension=".exe",
        file_type="application/x-executable",
        mime_type="application/octet-stream",
        metadata={
            "original_filename": "malware.exe",
            "extension": ".exe",
            "basename": "malware",
            "file_size": 1024,
            "detected_type": "unknown",
            "detected_subtype": "unknown",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    for ind in result["indicators"]:
        print(f"  - [{ind['severity']}] {ind['name']}: +{ind['points']}")
    assert result["score"] >= 25, f"Expected >= 25, got {result['score']}"
    assert result["risk_level"] in ("LOW", "SUSPICIOUS", "HIGH")
    print("  PASS\n")


def test_double_extension():
    print("=== Test 3: Double Extension ===")
    analysis = _make_analysis(
        filename="document.pdf.exe",
        extension=".exe",
        file_type="application/x-executable",
        mime_type="application/octet-stream",
        metadata={
            "original_filename": "document.pdf.exe",
            "extension": ".exe",
            "basename": "document.pdf",
            "file_size": 2048,
            "detected_type": "unknown",
            "detected_subtype": "unknown",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    for ind in result["indicators"]:
        print(f"  - [{ind['severity']}] {ind['name']}: +{ind['points']}")
    assert result["score"] >= 55, f"Expected >= 55, got {result['score']}"
    print("  PASS\n")


def test_extension_mismatch():
    print("=== Test 4: Extension Mismatch ===")
    analysis = _make_analysis(
        filename="report.pdf",
        extension=".pdf",
        file_type="text/plain",
        mime_type="text/plain",
        file_size=4096,
        metadata={
            "original_filename": "report.pdf",
            "extension": ".pdf",
            "basename": "report",
            "file_size": 4096,
            "detected_type": "text",
            "detected_subtype": "plain",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    for ind in result["indicators"]:
        print(f"  - [{ind['severity']}] {ind['name']}: +{ind['points']}")
    assert result["score"] >= 30, f"Expected >= 30, got {result['score']}"
    print("  PASS\n")


def test_suspicious_filename():
    print("=== Test 5: Suspicious Filename ===")
    analysis = _make_analysis(
        filename="confidential_invoice.txt",
        extension=".txt",
        file_type="text/plain",
        mime_type="text/plain",
        metadata={
            "original_filename": "confidential_invoice.txt",
            "extension": ".txt",
            "basename": "confidential_invoice",
            "file_size": 512,
            "detected_type": "text",
            "detected_subtype": "plain",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    for ind in result["indicators"]:
        print(f"  - [{ind['severity']}] {ind['name']}: +{ind['points']}")
    assert result["score"] >= 10, f"Expected >= 10, got {result['score']}"
    print("  PASS\n")


def test_high_risk_scenario():
    print("=== Test 6: High-Risk Scenario (multiple indicators) ===")
    analysis = _make_analysis(
        filename="secret_invoice.pdf.exe",
        extension=".exe",
        file_type="application/x-executable",
        mime_type="application/octet-stream",
        file_size=512,
        indicators=["Contains eval() call", "Contains base64 encoding"],
        metadata={
            "original_filename": "secret_invoice.pdf.exe",
            "extension": ".exe",
            "basename": "secret_invoice.pdf",
            "file_size": 512,
            "detected_type": "unknown",
            "detected_subtype": "unknown",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    for ind in result["indicators"]:
        print(f"  - [{ind['severity']}] {ind['name']}: +{ind['points']}")
    assert result["score"] == 100, f"Expected 100, got {result['score']}"
    assert result["risk_level"] == "HIGH", f"Expected HIGH, got {result['risk_level']}"
    assert len(result["indicators"]) >= 4
    print("  PASS\n")


def test_score_capped_at_100():
    print("=== Test 7: Score Capped at 100 ===")
    analysis = _make_analysis(
        filename="do.not.open.pdf.vbs.exe",
        extension=".exe",
        file_type="application/x-executable",
        mime_type="application/octet-stream",
        file_size=0,
        indicators=["Contains eval() call", "Contains base64 encoding", "Contains cmd.exe reference"],
        metadata={
            "original_filename": "do.not.open.pdf.vbs.exe",
            "extension": ".exe",
            "basename": "do.not.open.pdf.vbs",
            "file_size": 0,
            "detected_type": "unknown",
            "detected_subtype": "empty",
        },
    )
    result = evaluate_risk(analysis)
    print(f"  Score: {result['score']}")
    print(f"  Level: {result['risk_level']}")
    assert result["score"] <= 100, f"Score must be <= 100, got {result['score']}"
    print("  PASS\n")


def test_explanation_completeness():
    print("=== Test 8: Explanation Completeness ===")
    analysis = _make_analysis(
        filename="invoice.exe",
        extension=".exe",
        file_type="application/x-executable",
        mime_type="application/octet-stream",
        metadata={
            "original_filename": "invoice.exe",
            "extension": ".exe",
            "basename": "invoice",
            "file_size": 4096,
            "detected_type": "unknown",
            "detected_subtype": "unknown",
        },
    )
    result = evaluate_risk(analysis)
    explanation = result["explanation"]
    print(f"  Explanation preview: {explanation[:120]}...")
    assert "Risk Score:" in explanation
    assert "Triggered Rules:" in explanation
    assert result["risk_level"] in explanation
    print("  PASS\n")


def test_all_rules_return_structured():
    print("=== Test 9: All Rules Return Structured Data ===")
    analysis = _make_analysis()
    rules = run_all_rules(analysis)
    print(f"  Total rules: {len(rules)}")
    for rule in rules:
        d = rule.to_dict()
        assert "name" in d
        assert "description" in d
        assert "severity" in d
        assert "points" in d
        assert "detected" in d
        assert isinstance(d["points"], int)
        print(f"  - {d['name']}: detected={d['detected']}, points={d['points']}")
    print("  PASS\n")


if __name__ == "__main__":
    test_clean_text_file()
    test_executable_extension()
    test_double_extension()
    test_extension_mismatch()
    test_suspicious_filename()
    test_high_risk_scenario()
    test_score_capped_at_100()
    test_explanation_completeness()
    test_all_rules_return_structured()
    print("ALL TESTS PASSED")
