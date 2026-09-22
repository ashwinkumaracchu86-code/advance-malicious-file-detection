import io
import json
import sys
import time
import subprocess
import requests

BASE = "http://localhost:5000"
proc = None


def start_server():
    global proc
    proc = subprocess.Popen(
        ["python", "app.py"],
        cwd=r"D:\project 2\malicious-file-detection\backend",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(3)


def stop_server():
    if proc:
        proc.terminate()
        proc.wait(timeout=5)


def test_health():
    print("=== GET /api/health ===")
    r = requests.get(f"{BASE}/api/health")
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    print(f"  Status: {r.status_code}")
    print(f"  Message: {data['message']}")
    print("  PASS\n")


def test_scan_txt():
    print("=== POST /api/scan (harmless .txt) ===")
    content = b"This is a harmless text file for testing the scan endpoint."
    files = {"file": ("hello.txt", io.BytesIO(content), "text/plain")}
    r = requests.post(f"{BASE}/api/scan", files=files)
    data = r.json()
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {data}"
    assert data["success"] is True
    scan = data["data"]
    assert scan["filename"] == "hello.txt"
    assert scan["extension"] == ".txt"
    assert scan["md5"] != ""
    assert scan["sha256"] != ""
    assert scan["risk_score"] >= 0
    assert scan["risk_level"] in ("LOW", "SUSPICIOUS", "HIGH")
    print(f"  id: {scan['id']}")
    print(f"  filename: {scan['filename']}")
    print(f"  extension: {scan['extension']}")
    print(f"  file_type: {scan['file_type']}")
    print(f"  mime_type: {scan['mime_type']}")
    print(f"  file_size: {scan['file_size']}")
    print(f"  md5: {scan['md5']}")
    print(f"  sha256: {scan['sha256'][:32]}...")
    print(f"  risk_score: {scan['risk_score']}")
    print(f"  risk_level: {scan['risk_level']}")
    print("  PASS\n")
    return scan["id"]


def test_scan_pdf():
    print("=== POST /api/scan (harmless .pdf) ===")
    content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nThis is a fake PDF."
    files = {"file": ("report.pdf", io.BytesIO(content), "application/pdf")}
    r = requests.post(f"{BASE}/api/scan", files=files)
    data = r.json()
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {data}"
    assert data["success"] is True
    scan = data["data"]
    assert scan["filename"] == "report.pdf"
    assert scan["extension"] == ".pdf"
    print(f"  id: {scan['id']}")
    print(f"  filename: {scan['filename']}")
    print(f"  risk_score: {scan['risk_score']}")
    print(f"  risk_level: {scan['risk_level']}")
    print("  PASS\n")
    return scan["id"]


def test_scan_exe():
    print("=== POST /api/scan (harmless .exe - extension blocked) ===")
    content = b"MZ\x90\x00" + b"\x00" * 100
    files = {"file": ("suspicious.exe", io.BytesIO(content), "application/octet-stream")}
    r = requests.post(f"{BASE}/api/scan", files=files)
    data = r.json()
    assert r.status_code == 400, f"Expected 400 (blocked), got {r.status_code}: {data}"
    assert data["success"] is False
    print(f"  Status: {r.status_code}")
    print(f"  Error: {data['error']}")
    print("  PASS (extension blocked)\n")


def test_scan_empty():
    print("=== POST /api/scan (empty file) ===")
    files = {"file": ("empty.txt", io.BytesIO(b""), "text/plain")}
    r = requests.post(f"{BASE}/api/scan", files=files)
    data = r.json()
    assert r.status_code == 400, f"Expected 400, got {r.status_code}: {data}"
    assert data["success"] is False
    print(f"  Status: {r.status_code}")
    print(f"  Error: {data['error']}")
    print("  PASS\n")


def test_scan_no_file():
    print("=== POST /api/scan (no file) ===")
    r = requests.post(f"{BASE}/api/scan")
    data = r.json()
    assert r.status_code == 400, f"Expected 400, got {r.status_code}: {data}"
    assert data["success"] is False
    print(f"  Status: {r.status_code}")
    print(f"  Error: {data['error']}")
    print("  PASS\n")


def test_get_scans():
    print("=== GET /api/scans ===")
    r = requests.get(f"{BASE}/api/scans")
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    assert len(data["data"]) >= 2
    assert data["pagination"]["total"] >= 2
    print(f"  Total scans: {data['pagination']['total']}")
    print(f"  Page: {data['pagination']['page']}")
    print(f"  Returned: {len(data['data'])} scans")
    print("  PASS\n")


def test_get_scans_search():
    print("=== GET /api/scans?search=report ===")
    r = requests.get(f"{BASE}/api/scans", params={"search": "report"})
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    assert any("report" in s["filename"] for s in data["data"])
    print(f"  Found {len(data['data'])} result(s) matching 'report'")
    print("  PASS\n")


def test_get_scans_pagination():
    print("=== GET /api/scans?page=1&limit=1 ===")
    r = requests.get(f"{BASE}/api/scans", params={"page": 1, "limit": 1})
    data = r.json()
    assert r.status_code == 200
    assert len(data["data"]) == 1
    assert data["pagination"]["per_page"] == 1
    print(f"  Returned: {len(data['data'])} scan(s)")
    print(f"  Total pages: {data['pagination']['total_pages']}")
    print("  PASS\n")


def test_get_scan_by_id(scan_id):
    print(f"=== GET /api/scans/{scan_id} ===")
    r = requests.get(f"{BASE}/api/scans/{scan_id}")
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    assert data["data"]["id"] == scan_id
    assert "indicators" in data["data"]
    assert "metadata" in data["data"]
    print(f"  id: {data['data']['id']}")
    print(f"  filename: {data['data']['filename']}")
    print(f"  indicators: {len(data['data']['indicators'])} item(s)")
    print(f"  metadata keys: {list(data['data']['metadata'].keys())}")
    print("  PASS\n")


def test_get_scan_not_found():
    print("=== GET /api/scans/99999 ===")
    r = requests.get(f"{BASE}/api/scans/99999")
    data = r.json()
    assert r.status_code == 404
    assert data["success"] is False
    print(f"  Status: {r.status_code}")
    print(f"  Error: {data['error']}")
    print("  PASS\n")


def test_get_dashboard():
    print("=== GET /api/dashboard ===")
    r = requests.get(f"{BASE}/api/dashboard")
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    d = data["data"]
    assert d["total_scans"] >= 2
    assert "risk_distribution" in d
    assert "scan_activity" in d
    assert "recent_scans" in d
    print(f"  total_scans: {d['total_scans']}")
    print(f"  low_risk: {d['low_risk']}")
    print(f"  suspicious: {d['suspicious']}")
    print(f"  high_risk: {d['high_risk']}")
    print(f"  recent_scans: {len(d['recent_scans'])} item(s)")
    print(f"  scan_activity: {len(d['scan_activity'])} day(s)")
    print("  PASS\n")


def test_get_report(scan_id):
    print(f"=== GET /api/reports/{scan_id} ===")
    r = requests.get(f"{BASE}/api/reports/{scan_id}")
    data = r.json()
    assert r.status_code == 200
    assert data["success"] is True
    report = data["data"]
    assert "report_id" in report
    assert "explanation" in report
    assert "indicators" in report
    print(f"  report_id: {report['report_id']}")
    print(f"  filename: {report['filename']}")
    print(f"  risk_level: {report['risk_level']}")
    print(f"  explanation preview: {report['explanation'][:80]}...")
    print("  PASS\n")


def test_report_not_found():
    print("=== GET /api/reports/99999 ===")
    r = requests.get(f"{BASE}/api/reports/99999")
    data = r.json()
    assert r.status_code == 404
    assert data["success"] is False
    print(f"  Status: {r.status_code}")
    print(f"  Error: {data['error']}")
    print("  PASS\n")


if __name__ == "__main__":
    try:
        start_server()
        test_health()
        id1 = test_scan_txt()
        id2 = test_scan_pdf()
        test_scan_exe()
        test_scan_empty()
        test_scan_no_file()
        test_get_scans()
        test_get_scans_search()
        test_get_scans_pagination()
        test_get_scan_by_id(id1)
        test_get_scan_not_found()
        test_get_dashboard()
        test_get_report(id1)
        test_report_not_found()
        print("ALL TESTS PASSED")
    except Exception as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
    finally:
        stop_server()
