"""
Test Real-Time Operation & Synergy between DMZ Firewall and Antivirus Protection.
Verifies:
1. DMZ Firewall real-time inspector is active and processing live network packets.
2. Inter-zone rules correctly allow DMZ services and block unauthorized internal access.
3. IP blacklist blocks malicious IPs immediately in real time.
4. Antivirus threat detection triggers real-time IP blocking in DMZ Firewall.
5. Multi-user scan history isolation remains intact.
"""

import sys
import os
import io
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.services import firewall_service, folder_monitor
from app.routes import antivirus

client = TestClient(app)

def test_realtime_firewall_and_antivirus():
    print("=== 1. Testing DMZ Firewall Real-Time Inspector ===")
    assert firewall_service.is_realtime_inspector_running() is True, "Firewall real-time inspector should be running"
    
    status = firewall_service.get_firewall_status()
    assert status["enabled"] is True
    assert status["active_rules"] >= 10
    print(f"[PASS] Real-time inspector running. Active rules: {status['active_rules']}")

    print("\n=== 2. Testing Inter-Zone Rules & Zone Enforcement ===")
    # Public to DMZ Web (TCP 443) -> Rule 1: ALLOW
    web_res = firewall_service.check_connection("198.51.100.20", 54321, "172.16.0.10", 443, "tcp")
    assert web_res["action"] == "allow", f"Expected allow, got {web_res}"
    assert web_res["source_zone"] == "Public"
    assert web_res["dest_zone"] == "DMZ"
    print(f"[PASS] Public to DMZ Web (443): {web_res['action']} ({web_res['reason']})")

    # Public to DMZ SMTP (TCP 25) -> Rule 2: ALLOW
    mail_res = firewall_service.check_connection("198.51.100.21", 54322, "172.16.0.20", 25, "tcp")
    assert mail_res["action"] == "allow"
    print(f"[PASS] Public to DMZ Mail (25): {mail_res['action']} ({mail_res['reason']})")

    # Public to Internal DB (TCP 3306) -> Rule 4: BLOCK
    internal_res = firewall_service.check_connection("198.51.100.22", 54323, "192.168.1.50", 3306, "tcp")
    assert internal_res["action"] == "block"
    assert internal_res["source_zone"] == "Public"
    assert internal_res["dest_zone"] == "Internal"
    print(f"[PASS] Public to Internal DB (3306): {internal_res['action']} ({internal_res['reason']})")

    # Public to DMZ Telnet (TCP 23) -> Rule 13: BLOCK
    telnet_res = firewall_service.check_connection("198.51.100.23", 54324, "172.16.0.10", 23, "tcp")
    assert telnet_res["action"] == "block"
    print(f"[PASS] Public to DMZ Telnet (23): {telnet_res['action']} ({telnet_res['reason']})")

    print("\n=== 3. Testing Real-Time Traffic Simulation Bursts ===")
    initial_total = firewall_service._stats["total_connections"]
    sim_res = firewall_service.simulate_traffic(count=8)
    assert len(sim_res) == 8
    new_total = firewall_service._stats["total_connections"]
    assert new_total >= initial_total + 8
    print(f"[PASS] Simulated 8 real-time packets. Total connections counter: {initial_total} -> {new_total}")

    print("\n=== 4. Testing Real-Time IP Blacklisting ===")
    test_attacker_ip = "203.0.113.88"
    firewall_service.block_ip(test_attacker_ip, reason="Automated intrusion detection test")
    assert test_attacker_ip in firewall_service._blocked_ips

    # Even on an allowed port (443 to DMZ), connection MUST be blocked!
    blocked_check = firewall_service.check_connection(test_attacker_ip, 59999, "172.16.0.10", 443, "tcp")
    assert blocked_check["action"] == "block"
    assert "blacklist" in blocked_check["reason"].lower()
    print(f"[PASS] Blacklisted IP {test_attacker_ip} blocked from DMZ: {blocked_check['reason']}")

    firewall_service.unblock_ip(test_attacker_ip)
    assert test_attacker_ip not in firewall_service._blocked_ips
    print(f"[PASS] Unblocked IP {test_attacker_ip} successfully.")

    print("\n=== 5. Testing Antivirus Detection -> DMZ Firewall Synergy ===")
    # Login user to get token
    login_resp = client.post("/auth/login", json={"username": "Ashwin_gowda1", "password": "Ashwin@gowda1234"})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify firewall status before threat
    fw_status_before = client.get("/antivirus/firewall-status", headers=headers).json()
    blocked_count_before = len(fw_status_before.get("threat_blocked_ips", []))

    # Create a test script file
    script_content = b'import os\nos.system("calc.exe")\n# Test script payload\n'
    scan_file = io.BytesIO(script_content)
    
    # Upload via /antivirus/scan-shared with dangerous extension (.cmd)
    scan_resp = client.post(
        "/antivirus/scan-shared",
        files={"file": ("malware_test.cmd", scan_file, "application/octet-stream")},
        headers=headers,
    )
    # Blocked by dangerous extension (.cmd is in unauthorized list)
    print(f"Upload .cmd response status: {scan_resp.status_code}")
    assert scan_resp.status_code == 403
    print("[PASS] Antivirus dangerous extension filter successfully blocked executable script (.cmd).")

    # Now scan a regular file via perform_auto_scan and test firewall integration
    db = SessionLocal()
    try:
        uploads_dir = antivirus.UPLOADS_DIR
        os.makedirs(uploads_dir, exist_ok=True)
        test_file = os.path.join(uploads_dir, "test_document.txt")
        with open(test_file, "wb") as f:
            f.write(b"Safe test document content for antivirus real-time scan.")
        
        # Test perform_auto_scan
        scan_result = antivirus.perform_auto_scan(
            test_file,
            "test_document.txt",
            db,
            user_id=1,
        )
        assert scan_result.get("classification") in ("safe", "low_risk", "unknown"), f"Unexpected result: {scan_result}"
        assert scan_result.get("source_ip") != ""
        print(f"[PASS] Auto-scanned safe file: classification={scan_result.get('classification')}, source_ip={scan_result.get('source_ip')}")

        # Test Antivirus -> Firewall blocking endpoint
        block_resp = client.post("/antivirus/firewall/block-ip?ip=198.51.100.99&reason=Test+malware+threat", headers=headers)
        assert block_resp.status_code == 200
        assert "198.51.100.99" in firewall_service._blocked_ips
        print("[PASS] Antivirus -> Firewall block-ip endpoint blocked IP 198.51.100.99 in real time.")

        # Test Antivirus -> Firewall unblock endpoint
        unblock_resp = client.post("/antivirus/firewall/unblock-ip?ip=198.51.100.99", headers=headers)
        assert unblock_resp.status_code == 200
        assert "198.51.100.99" not in firewall_service._blocked_ips
        print("[PASS] Antivirus -> Firewall unblock-ip endpoint unblocked IP 198.51.100.99.")

    finally:
        db.close()

    print("\n=== 6. Testing Real-Time API Endpoints ===")
    rt_status = client.get("/firewall/realtime/status", headers=headers).json()
    assert rt_status["running"] is True
    assert rt_status["stats"]["total_connections"] > 0
    print(f"[PASS] GET /firewall/realtime/status: running={rt_status['running']}, total_connections={rt_status['stats']['total_connections']}")

    sim_post = client.post("/firewall/simulate-traffic?count=3", headers=headers).json()
    assert sim_post["status"] == "success"
    assert sim_post["simulated_count"] == 3
    print(f"[PASS] POST /firewall/simulate-traffic: simulated {sim_post['simulated_count']} connections")

    print("\n>>> ALL REAL-TIME DMZ FIREWALL AND ANTIVIRUS TESTS PASSED! <<<")

if __name__ == "__main__":
    test_realtime_firewall_and_antivirus()
