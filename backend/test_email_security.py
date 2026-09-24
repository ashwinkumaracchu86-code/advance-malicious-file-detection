"""Standalone tests for the Email Security / Email Monitor feature.

Run:  venv/scripts/python.exe test_email_security.py
These tests exercise the real analysis pipeline (parser, sender/subject/body/URL
analyzers, attachment scanner, risk engine) against the 12 spec test cases.
"""

import email
import io
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from email.message import EmailMessage

from app.services.email_monitor_service import (
    parse_eml_content,
    analyze_sender,
    analyze_subject,
    analyze_body,
    analyze_attachment,
    get_auth_results,
)
from app.services.url_scanner import extract_and_analyze_urls, get_url_summary
from app.services.email_risk_engine import calculate_email_risk_score
from app.models.email_models import EmailProcessedUID

PASS = 0
FAIL = 0


def _build_eml(
    body_text="Hello, this is a normal message.",
    body_html="",
    sender="alice@example.com",
    display_name="Alice",
    recipient="bob@example.com",
    subject="Project update",
    attachments=None,
    extra_headers=None,
):
    msg = EmailMessage()
    extra_headers = dict(extra_headers or {})
    msg["From"] = extra_headers.pop("From", f"{display_name} <{sender}>" if display_name else sender)
    msg["To"] = extra_headers.pop("To", recipient)
    msg["Subject"] = extra_headers.pop("Subject", subject)
    msg["Date"] = extra_headers.pop("Date", "Thu, 12 Jun 2025 10:00:00 +0000")
    msg["Message-ID"] = extra_headers.pop("Message-ID", "<test-12345@example.com>")
    for name, value in extra_headers.items():
        msg[name] = value
    if body_html:
        msg.set_content(body_html, subtype="html")
        msg.add_alternative(body_text, subtype="plain")
    else:
        msg.set_content(body_text)
    for att in attachments or []:
        msg.add_attachment(
            att.get("data", b""),
            maintype=att.get("maintype", "application"),
            subtype=att.get("subtype", "octet-stream"),
            filename=att.get("filename", "file.bin"),
        )
    return msg.as_bytes()


def _full_analysis(raw_eml):
    parsed = parse_eml_content(raw_eml)
    sender_analysis = analyze_sender(parsed["sender"], parsed["display_name"], parsed["headers"])
    subject_analysis = analyze_subject(parsed["subject"])
    body_analysis = analyze_body(parsed["body_text"], parsed["body_html"])
    url_analyses = extract_and_analyze_urls(parsed["body_text"], parsed["body_html"])
    url_summary = get_url_summary(url_analyses)
    attachment_analyses = [analyze_attachment(a, 25) for a in parsed["attachments"]]
    risk = calculate_email_risk_score(
        sender_analysis=sender_analysis, subject_analysis=subject_analysis,
        body_analysis=body_analysis, url_analyses=url_analyses,
        attachment_analyses=attachment_analyses,
    )
    return {
        "parsed": parsed,
        "sender_analysis": sender_analysis,
        "subject_analysis": subject_analysis,
        "body_analysis": body_analysis,
        "url_analyses": url_analyses,
        "url_summary": url_summary,
        "attachment_analyses": attachment_analyses,
        "risk": risk,
    }


def check(name, condition, extra=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}{' - ' + str(extra) if extra else ''}")
    else:
        FAIL += 1
        print(f"  FAIL: {name}{' - ' + str(extra) if extra else ''}")


def test_normal_text_email():
    print("\n=== 1. Fully normal text email (should be SAFE) ===")
    raw = _build_eml(body_text="Hi, please review the attached quarterly numbers when you get a chance.")
    r = _full_analysis(raw)
    print(f"  sender_score={r['sender_analysis']['score']} subject_score={r['subject_analysis']['score']} "
          f"body_score={r['body_analysis']['score']} urls={r['url_summary']['total_urls']} "
          f"risk_score={r['risk']['risk_score']} classification={r['risk']['classification']}")
    check("sender has no risk", r["sender_analysis"]["score"] == 0, str(r["sender_analysis"]["reasons"]))
    check("subject has no risk", r["subject_analysis"]["score"] == 0)
    check("url summary is zero", r["url_summary"]["total_urls"] == 0)
    check("email classified safe", r["risk"]["classification"] == "safe",
          f"got {r['risk']['classification']}")


def test_known_trusted_sender():
    print("\n=== 2. Email from a known/trusted domain (should stay clean) ===")
    raw = _build_eml(
        sender="noreply@microsoft.com", display_name="Microsoft",
        body_text="Your monthly digest is ready.",
        extra_headers={"Authentication-Results": "mx.example.com; spf=pass smtp.mailfrom=microsoft.com"},
    )
    r = _full_analysis(raw)
    print(f"  sender_domain={r['parsed']['sender']} sender_score={r['sender_analysis']['score']} "
          f"spf={r['parsed']['headers'].get('Authentication-Results')}")
    check("trusted domain sender has no spoofing flags", r["sender_analysis"]["score"] == 0,
          str(r["sender_analysis"]["reasons"]))
    check("email not malicious", r["risk"]["classification"] in ("safe", "low_risk"))


def test_image_attachment():
    print("\n=== 3. Email with an image attachment (should be SAFE) ===")
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200 + b"IEND\xaeB`\x82"
    raw = _build_eml(body_text="See the photo attached.", attachments=[
        {"filename": "photo.png", "data": png, "maintype": "image", "subtype": "png"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} scanned={a['scanned']} "
          f"mx={a.get('is_mime_mismatch', False)}")
    check("image attachment was scanned", a["scanned"] is True)
    check("image attachment classified safe", a["classification"] == "safe", a.get("detection_reasons", []))
    check("email overall not malicious", r["risk"]["classification"] in ("safe", "low_risk"))


def test_normal_document_attachment():
    print("\n=== 4. Email with a normal document (should be SAFE) ===")
    txt = b"This is a normal invoice document containing no suspicious content."
    raw = _build_eml(body_text="Please find the invoice.", attachments=[
        {"filename": "invoice.txt", "data": txt, "maintype": "text", "subtype": "plain"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} scanned={a['scanned']}")
    check("document attachment was scanned", a["scanned"] is True)
    check("document classified safe", a["classification"] == "safe", a.get("detection_reasons", []))


def test_suspicious_url():
    print("\n=== 5. Email with a suspicious URL (URL analysis must flag it) ===")
    raw = _build_eml(
        body_text="Click here to verify your account: http://security-verify-login.xyz/login",
        extra_headers={"From": "attacker@evildomain.xyz"},
    )
    r = _full_analysis(raw)
    print(f"  urls={r['url_summary']['total_urls']} suspicious={r['url_summary']['suspicious_urls']} "
          f"phishing={r['url_summary']['phishing_urls']}")
    check("suspicious URL extracted", r["url_summary"]["total_urls"] >= 1)
    check("suspicious URL flagged", r["url_summary"]["suspicious_urls"] >= 1)
    check("url reasons non-empty", any(u.get("reasons") for u in r["url_analyses"]))
    check("email risk elevated", r["risk"]["classification"] in ("low_risk", "suspicious", "malicious", "critical"),
          f"got {r['risk']['classification']}")


def test_html_attachment_with_script():
    print("\n=== 6. Email with an HTML attachment containing script (should be flagged) ===")
    html = b'<html><body><script>document.write(String.fromCharCode(104,116,116,112));</script><form action="http://fake/login"><input name="password"></form></body></html>'
    raw = _build_eml(body_text="See the attachment.", attachments=[
        {"filename": "page.html", "data": html, "maintype": "text", "subtype": "html"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} "
          f"reasons={a.get('detection_reasons', [])}")
    check("html attachment scanned", a["scanned"] is True)
    check("html attachment is not clean", a["classification"] in ("suspicious", "malicious") or a["risk_score"] > 0,
          f"class={a['classification']} risk={a['risk_score']}")


def test_executable_attachment():
    print("\n=== 7. Email with an executable attachment (must be flagged) ===")
    exe = b"MZ" + b"\x00" * 64 + b"powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA XOR cmd.exe /c net user"
    raw = _build_eml(body_text="Run this program.", attachments=[
        {"filename": "installer.exe", "data": exe, "maintype": "application", "subtype": "x-msdownload"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} "
          f"dangerous_ext={a.get('is_dangerous_extension')} reasons={a.get('detection_reasons', [])}")
    check("executable scanned", a["scanned"] is True)
    check("executable flagged as dangerous extension", a.get("is_dangerous_extension") is True)
    check("executable risk above zero", a["risk_score"] > 0, f"risk={a['risk_score']}")
    check("email overall not safe", r["risk"]["classification"] in ("low_risk", "suspicious", "malicious", "critical"),
          f"got {r['risk']['classification']}")


def test_suspicious_archive():
    print("\n=== 8. Email with a suspicious archive (should be assessed) ===")
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "looks normal")
    raw = _build_eml(body_text="Archive attached.", attachments=[
        {"filename": "docs.zip", "data": buf.getvalue(), "maintype": "application", "subtype": "zip"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} scanned={a['scanned']}")
    check("archive was scanned", a["scanned"] is True)
    check("archive analysis completed without error", a.get("skipped_reason") is None)


def test_eicar_signature():
    print("\n=== 9. EICAR test file (must be detected as known threat) ===")
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    raw = _build_eml(body_text="Check this file.", attachments=[
        {"filename": "eicar.txt", "data": eicar, "maintype": "text", "subtype": "plain"},
    ])
    r = _full_analysis(raw)
    a = r["attachment_analyses"][0]
    print(f"  attachment class={a['classification']} risk={a['risk_score']} "
          f"eicar={a.get('eicar_detected')} reasons={a.get('detection_reasons', [])}")
    check("EICAR attachment flagged malicious", a["classification"] == "malicious", f"got {a['classification']}")
    check("EICAR reason recorded", "EICAR" in str(a.get("detection_reasons", [])))
    check("email overall classified threat", r["risk"]["classification"] in ("suspicious", "malicious", "critical"),
          f"got {r['risk']['classification']}")


def test_multiple_attachments():
    print("\n=== 10. Email with multiple attachments (each must be analyzed) ===")
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200 + b"IEND\xaeB`\x82"
    raw = _build_eml(body_text="Several files.", attachments=[
        {"filename": "a.png", "data": png, "maintype": "image", "subtype": "png"},
        {"filename": "readme.txt", "data": b"hello world", "maintype": "text", "subtype": "plain"},
        {"filename": "run.bat", "data": b"@echo off\r\nnet user hacker /add\r\npowershell -enc xxx",
         "maintype": "application", "subtype": "x-msdownload"},
    ])
    r = _full_analysis(raw)
    print(f"  parsed_attachments={len(r['parsed']['attachments'])} analyzed={len(r['attachment_analyses'])} "
          f"classes={[a['classification'] for a in r['attachment_analyses']]}")
    check("all 3 attachments parsed", len(r["parsed"]["attachments"]) == 3)
    check("all 3 attachments analyzed", len(r["attachment_analyses"]) == 3)
    check("all attachments scanned", all(a["scanned"] is True for a in r["attachment_analyses"]))
    check("malicious .bat flagged", r["attachment_analyses"][2]["classification"] in ("suspicious", "malicious"))


def test_duplicate_message_id():
    print("\n=== 11. Duplicate email protection (same Message-ID must dedupe) ===")
    raw = _build_eml(body_text="Duplicate me.")
    r1 = parse_eml_content(raw)
    r2 = parse_eml_content(raw)
    print(f"  message_id_1={r1['message_id']} message_id_2={r2['message_id']}")
    check("same Message-ID parsed identically", r1["message_id"] == r2["message_id"]
          and r1["message_id"].startswith("<test-12345@example.com>"))
    check("processed-UID unique constraint exists",
          any(c.name == "uq_config_folder_uid" for c in EmailProcessedUID.__table__.constraints))


def test_mixed_content_email():
    print("\n=== 12. Email mixing safe + suspicious content (overall should reflect risks) ===")
    exe = b"MZ" + b"\x00" * 64 + b"powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA XOR cmd.exe /c net user"
    raw = _build_eml(
        body_text="Normal intro. Verify: http://verify-account-update.xyz/login",
        sender="scam@fake-secure.xyz",
        attachments=[
            {"filename": "photo.png", "data": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"IEND\xaeB`\x82",
             "maintype": "image", "subtype": "png"},
            {"filename": "update.exe", "data": exe, "maintype": "application", "subtype": "x-msdownload"},
        ],
    )
    r = _full_analysis(raw)
    print(f"  safe_attachment={r['attachment_analyses'][0]['classification']} "
          f"bad_attachment={r['attachment_analyses'][1]['classification']} "
          f"suspicious_urls={r['url_summary']['suspicious_urls']} "
          f"overall_class={r['risk']['classification']} risk={r['risk']['risk_score']}")
    check("safe image still safe", r["attachment_analyses"][0]["classification"] == "safe")
    check("suspicious URL flagged", r["url_summary"]["suspicious_urls"] >= 1)
    check("executable flagged", r["attachment_analyses"][1]["classification"] in ("suspicious", "malicious"))
    check("overall email classified as threat",
          r["risk"]["classification"] in ("suspicious", "malicious", "critical"),
          f"got {r['risk']['classification']}")


if __name__ == "__main__":
    test_normal_text_email()
    test_known_trusted_sender()
    test_image_attachment()
    test_normal_document_attachment()
    test_suspicious_url()
    test_html_attachment_with_script()
    test_executable_attachment()
    test_suspicious_archive()
    test_eicar_signature()
    test_multiple_attachments()
    test_duplicate_message_id()
    test_mixed_content_email()
    print(f"\n===== RESULT: {PASS} passed, {FAIL} failed =====")
    sys.exit(1 if FAIL else 0)