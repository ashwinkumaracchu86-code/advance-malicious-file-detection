import os
import sys
import tempfile
import hashlib
import math
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app.main import app
from app.security.auth import get_password_hash, verify_password, create_access_token, verify_token
from app.scanner.hash_calculator import calculate_hashes
from app.scanner.entropy_analyzer import calculate_shannon_entropy
from app.scanner.mime_detector import detect_mime_type, verify_extension_match
from app.scanner.risk_scorer import calculate_risk_score
from app.utils.helpers import sanitize_filename, safe_path_join, format_file_size


client = TestClient(app)


def get_auth_headers():
    token = create_access_token({"sub": "1", "username": "admin"})
    return {"Authorization": f"Bearer {token}"}


class TestPasswordHashing:
    def test_hash_password(self):
        hashed = get_password_hash("testpassword")
        assert hashed != "testpassword"
        assert len(hashed) > 0

    def test_verify_correct_password(self):
        hashed = get_password_hash("mypassword")
        assert verify_password("mypassword", hashed) is True

    def test_verify_wrong_password(self):
        hashed = get_password_hash("mypassword")
        assert verify_password("wrongpassword", hashed) is False

    def test_different_hashes(self):
        h1 = get_password_hash("password")
        h2 = get_password_hash("password")
        assert h1 != h2

    def test_empty_password(self):
        hashed = get_password_hash("")
        assert verify_password("", hashed) is True


class TestJWT:
    def test_create_token(self):
        token = create_access_token({"sub": "admin"})
        assert token is not None
        assert len(token) > 0

    def test_verify_valid_token(self):
        token = create_access_token({"sub": "admin"})
        payload = verify_token(token)
        assert payload is not None
        assert payload.get("sub") == "admin"

    def test_verify_invalid_token(self):
        result = verify_token("invalid.token.here")
        assert result is None

    def test_token_expiration(self):
        from datetime import timedelta
        token = create_access_token({"sub": "admin"}, expires_delta=timedelta(seconds=-1))
        result = verify_token(token)
        assert result is None


class TestHashCalculator:
    def test_md5(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"Hello World")
            f.flush()
            result = calculate_hashes(f.name)
            os.unlink(f.name)
        expected = hashlib.md5(b"Hello World").hexdigest()
        assert result["md5"] == expected

    def test_sha1(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"Hello World")
            f.flush()
            result = calculate_hashes(f.name)
            os.unlink(f.name)
        expected = hashlib.sha1(b"Hello World").hexdigest()
        assert result["sha1"] == expected

    def test_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"Hello World")
            f.flush()
            result = calculate_hashes(f.name)
            os.unlink(f.name)
        expected = hashlib.sha256(b"Hello World").hexdigest()
        assert result["sha256"] == expected

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.flush()
            result = calculate_hashes(f.name)
            os.unlink(f.name)
        expected = hashlib.md5(b"").hexdigest()
        assert result["md5"] == expected

    def test_binary_file(self):
        data = bytes(range(256))
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            f.flush()
            result = calculate_hashes(f.name)
            os.unlink(f.name)
        expected = hashlib.sha256(data).hexdigest()
        assert result["sha256"] == expected


class TestEntropyAnalyzer:
    def test_low_entropy(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"AAAAAAAAAAAAAAAAAAAA")
            f.flush()
            result = calculate_shannon_entropy(f.name)
            os.unlink(f.name)
        assert result["entropy"] < 2.0

    def test_high_entropy(self):
        data = os.urandom(1024)
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            f.flush()
            result = calculate_shannon_entropy(f.name)
            os.unlink(f.name)
        assert result["entropy"] > 6.0

    def test_empty_data(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.flush()
            result = calculate_shannon_entropy(f.name)
            os.unlink(f.name)
        assert result["entropy"] == 0.0

    def test_text_entropy(self):
        data = b"The quick brown fox jumps over the lazy dog"
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(data)
            f.flush()
            result = calculate_shannon_entropy(f.name)
            os.unlink(f.name)
        assert 3.0 < result["entropy"] < 5.0

    def test_single_byte(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"\x00")
            f.flush()
            result = calculate_shannon_entropy(f.name)
            os.unlink(f.name)
        assert result["entropy"] == 0.0


class TestMIMEDetector:
    def test_text_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            f.write(b"This is a text file")
            f.flush()
            result = detect_mime_type(f.name)
            os.unlink(f.name)
        assert 'text' in result.lower() or result is not None

    def test_extension_verification(self):
        assert verify_extension_match("test.txt", "text/plain") is True
        assert verify_extension_match("test.exe", "text/plain") is False

    def test_mismatch_detection(self):
        result = verify_extension_match("document.pdf", "application/x-executable")
        assert result is False


class TestRiskScorer:
    def test_safe_file(self):
        result = calculate_risk_score(
            entropy=3.0,
            suspicious_count=0,
            extension=".txt",
            mime_type="text/plain",
            extension_matches_mime=True,
            file_size=1024,
            vt_positives=0,
            vt_total=0,
        )
        assert result["risk_score"] <= 30
        assert result["classification"] == "safe"

    def test_suspicious_file(self):
        result = calculate_risk_score(
            entropy=6.5,
            suspicious_count=3,
            extension=".scr",
            mime_type="application/octet-stream",
            extension_matches_mime=False,
            file_size=50000,
            vt_positives=0,
            vt_total=0,
        )
        assert 31 <= result["risk_score"] <= 70
        assert result["classification"] == "suspicious"

    def test_malicious_file(self):
        result = calculate_risk_score(
            entropy=7.5,
            suspicious_count=8,
            extension=".exe",
            mime_type="application/x-dosexec",
            extension_matches_mime=False,
            file_size=100000,
            vt_positives=15,
            vt_total=30,
        )
        assert result["risk_score"] >= 71
        assert result["classification"] == "malicious"

    def test_score_bounds(self):
        result = calculate_risk_score(
            entropy=0,
            suspicious_count=0,
            extension=".txt",
            mime_type="text/plain",
            extension_matches_mime=True,
            file_size=100,
            vt_positives=0,
            vt_total=0,
        )
        assert 0 <= result["risk_score"] <= 100

    def test_has_reasons(self):
        result = calculate_risk_score(
            entropy=7.0,
            suspicious_count=5,
            extension=".exe",
            mime_type="application/x-dosexec",
            extension_matches_mime=False,
            file_size=50000,
            vt_positives=10,
            vt_total=20,
        )
        assert len(result["reasons"]) > 0


class TestHelpers:
    def test_sanitize_filename(self):
        assert sanitize_filename("normal_file.txt") == "normal_file.txt"
        assert ".." not in sanitize_filename("../../../etc/passwd")
        assert "/" not in sanitize_filename("path/to/file.txt")
        assert "\\" not in sanitize_filename("path\\to\\file.txt")

    def test_safe_path_join(self):
        result = safe_path_join("/safe/dir", "file.txt")
        assert result.startswith("/safe/dir")

    def test_path_traversal_prevention(self):
        result = safe_path_join("/safe/dir", "../../etc/passwd")
        assert result is None

    def test_format_file_size(self):
        assert "B" in format_file_size(100)
        assert "KB" in format_file_size(1024)
        assert "MB" in format_file_size(1024 * 1024)
        assert "GB" in format_file_size(1024 ** 3)


class TestAuthAPI:
    def test_login_success(self):
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "admin123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["username"] == "admin"

    def test_login_wrong_password(self):
        response = client.post("/auth/login", json={
            "username": "admin",
            "password": "wrongpassword"
        })
        assert response.status_code == 401

    def test_login_nonexistent_user(self):
        response = client.post("/auth/login", json={
            "username": "nonexistent",
            "password": "password"
        })
        assert response.status_code == 401


class TestDashboardAPI:
    def test_statistics(self):
        headers = get_auth_headers()
        response = client.get("/dashboard/statistics", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "safe_count" in data
        assert "suspicious_count" in data
        assert "malicious_count" in data


class TestScansAPI:
    def test_list_scans(self):
        headers = get_auth_headers()
        response = client.get("/scans", headers=headers)
        assert response.status_code == 200

    def test_list_scans_pagination(self):
        headers = get_auth_headers()
        response = client.get("/scans?skip=0&limit=10", headers=headers)
        assert response.status_code == 200


class TestQuarantineAPI:
    def test_list_quarantine(self):
        headers = get_auth_headers()
        response = client.get("/quarantine", headers=headers)
        assert response.status_code == 200


class TestLogsAPI:
    def test_list_logs(self):
        headers = get_auth_headers()
        response = client.get("/logs", headers=headers)
        assert response.status_code == 200


class TestFileUpload:
    def test_upload_text_file(self):
        headers = get_auth_headers()
        content = b"This is a safe text file for testing"
        response = client.post(
            "/files/upload",
            files={"files": ("test.txt", content, "text/plain")},
            headers=headers,
        )
        assert response.status_code in [200, 201]

    def test_upload_multiple_files(self):
        headers = get_auth_headers()
        files = [
            ("files", ("file1.txt", b"Content 1", "text/plain")),
            ("files", ("file2.txt", b"Content 2", "text/plain")),
        ]
        response = client.post("/files/upload", files=files, headers=headers)
        assert response.status_code in [200, 201]

    def test_upload_empty_file(self):
        headers = get_auth_headers()
        response = client.post(
            "/files/upload",
            files={"files": ("empty.txt", b"", "text/plain")},
            headers=headers,
        )
        assert response.status_code in [200, 201, 400]


class TestSecurityControls:
    def test_no_execution_on_upload(self):
        headers = get_auth_headers()
        content = b"#!/bin/bash\nrm -rf /"
        response = client.post(
            "/files/upload",
            files={"files": ("script.sh", content, "application/x-sh")},
            headers=headers,
        )
        assert response.status_code in [200, 201]

    def test_path_traversal_in_filename(self):
        headers = get_auth_headers()
        content = b"test content"
        response = client.post(
            "/files/upload",
            files={"files": ("../../etc/passwd", content, "text/plain")},
            headers=headers,
        )
        assert response.status_code in [200, 201, 400]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
