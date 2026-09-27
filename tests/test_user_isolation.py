import asyncio
import os
import sys
import threading
import time
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.main import app
from app.services.ws_manager import ConnectionManager

PASSWORD = "Iso#UserPass1"


def _auth(client, tag):
    """Register + log in a unique user and return (headers, user_id)."""
    name = f"iso_{tag}_{uuid.uuid4().hex[:8]}"
    res = client.post(
        "/auth/register",
        json={"username": name, "email": f"{name}@example.test", "password": PASSWORD},
    )
    assert res.status_code == 201, res.text
    res = client.post("/auth/login", json={"username": name, "password": PASSWORD})
    assert res.status_code == 200, res.text
    body = res.json()
    return {"Authorization": f"Bearer {body['access_token']}"}, body["user"]["id"]


def _upload(client, headers, filename, content):
    res = client.post(
        "/files/upload",
        files={"files": (filename, content, "text/plain")},
        headers=headers,
    )
    assert res.status_code in (200, 201), res.text
    results = res.json().get("results", [])
    assert results and "file" in results[0], res.json()
    return results[0]["file"], results[0]["scan"]


@pytest.fixture(scope="module")
def ctx():
    with TestClient(app) as client:
        # Isolated rate-limit bucket so this suite never trips the limiter.
        client.headers.update({"X-Forwarded-For": f"10.9.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"})

        a_headers, a_id = _auth(client, "a")
        b_headers, b_id = _auth(client, "b")

        file_a, scan_a = _upload(
            client, a_headers, "user_a_secret.txt", b"USER_A_PRIVATE_CONTENT_12345"
        )
        file_b, scan_b = _upload(
            client, b_headers, "user_b_secret.txt", b"USER_B_PRIVATE_CONTENT_67890"
        )

        yield SimpleNamespace(
            client=client,
            a_headers=a_headers,
            a_id=a_id,
            b_headers=b_headers,
            b_id=b_id,
            file_a=file_a,
            scan_a=scan_a,
            file_b=file_b,
            scan_b=scan_b,
        )


class TestFileIsolation:
    def test_each_user_only_sees_own_files(self, ctx):
        a_files = ctx.client.get("/files", headers=ctx.a_headers).json()
        b_files = ctx.client.get("/files", headers=ctx.b_headers).json()

        a_ids = {f["id"] for f in a_files}
        b_ids = {f["id"] for f in b_files}

        assert ctx.file_a["id"] in a_ids
        assert ctx.file_b["id"] not in a_ids
        assert ctx.file_b["id"] in b_ids
        assert ctx.file_a["id"] not in b_ids

        assert all(f["uploaded_by"] == ctx.a_id for f in a_files)
        assert all(f["uploaded_by"] == ctx.b_id for f in b_files)

        assert "user_a_secret.txt" not in {f["original_filename"] for f in b_files}
        assert "user_b_secret.txt" not in {f["original_filename"] for f in a_files}

    def test_user_cannot_read_other_users_file(self, ctx):
        res = ctx.client.get(f"/files/{ctx.file_b['id']}", headers=ctx.a_headers)
        assert res.status_code == 403
        res = ctx.client.get(f"/files/{ctx.file_a['id']}", headers=ctx.b_headers)
        assert res.status_code == 403

    def test_owner_can_read_own_file(self, ctx):
        res = ctx.client.get(f"/files/{ctx.file_a['id']}", headers=ctx.a_headers)
        assert res.status_code == 200
        assert res.json()["original_filename"] == "user_a_secret.txt"

    def test_missing_file_is_not_distinguishable_from_foreign(self, ctx):
        res = ctx.client.get("/files/99999999", headers=ctx.a_headers)
        assert res.status_code == 403


class TestScanIsolation:
    def test_user_cannot_trigger_scan_on_foreign_file(self, ctx):
        res = ctx.client.post(f"/scan/{ctx.file_b['id']}", headers=ctx.a_headers)
        assert res.status_code == 403
        res = ctx.client.post(f"/scan/{ctx.file_a['id']}", headers=ctx.b_headers)
        assert res.status_code == 403

    def test_scan_list_is_scoped(self, ctx):
        res = ctx.client.get("/scans?limit=200", headers=ctx.a_headers)
        assert res.status_code == 200
        scans = res.json()["scans"]
        assert all(s["user_id"] == ctx.a_id for s in scans)
        assert ctx.scan_b["id"] not in {s["id"] for s in scans}
        assert ctx.scan_a["id"] in {s["id"] for s in scans}

        res = ctx.client.get("/scans?limit=200", headers=ctx.b_headers)
        scans = res.json()["scans"]
        assert all(s["user_id"] == ctx.b_id for s in scans)
        assert ctx.scan_a["id"] not in {s["id"] for s in scans}

    def test_user_cannot_read_foreign_scan_result(self, ctx):
        res = ctx.client.get(f"/scan/{ctx.scan_b['id']}", headers=ctx.a_headers)
        assert res.status_code == 403
        res = ctx.client.get(f"/scan/{ctx.scan_a['id']}", headers=ctx.b_headers)
        assert res.status_code == 403

    def test_owner_can_read_own_scan_result(self, ctx):
        res = ctx.client.get(f"/scan/{ctx.scan_a['id']}", headers=ctx.a_headers)
        assert res.status_code == 200
        assert res.json()["user_id"] == ctx.a_id

    def test_report_download_is_scoped(self, ctx):
        res = ctx.client.get(f"/reports/{ctx.scan_b['id']}", headers=ctx.a_headers)
        assert res.status_code == 403
        res = ctx.client.get(f"/reports/{ctx.scan_a['id']}", headers=ctx.a_headers)
        assert res.status_code == 200


class TestQuarantineIsolation:
    def _ensure_quarantine_a(self, ctx):
        """Quarantine file A (idempotent) and return the quarantine item."""
        listing = ctx.client.get("/quarantine", headers=ctx.a_headers).json()
        existing = [i for i in listing if i["original_filename"] == "user_a_secret.txt"]
        if existing:
            return existing[0]
        res = ctx.client.post(f"/quarantine/{ctx.file_a['id']}", headers=ctx.a_headers)
        assert res.status_code == 201, res.text
        return res.json()

    def test_quarantine_requires_file_ownership(self, ctx):
        res = ctx.client.post(f"/quarantine/{ctx.file_b['id']}", headers=ctx.a_headers)
        assert res.status_code == 403

    def test_quarantine_list_is_scoped(self, ctx):
        item_a = self._ensure_quarantine_a(ctx)
        a_items = ctx.client.get("/quarantine", headers=ctx.a_headers).json()
        b_items = ctx.client.get("/quarantine", headers=ctx.b_headers).json()

        assert all(i["user_id"] == ctx.a_id for i in a_items)
        assert all(i["user_id"] == ctx.b_id for i in b_items)
        assert item_a["id"] in {i["id"] for i in a_items}
        assert item_a["id"] not in {i["id"] for i in b_items}

    def test_user_cannot_restore_or_delete_foreign_quarantine_item(self, ctx):
        item_id = self._ensure_quarantine_a(ctx)["id"]

        res = ctx.client.post(f"/quarantine/{item_id}/restore", headers=ctx.b_headers)
        assert res.status_code == 403
        res = ctx.client.delete(f"/quarantine/{item_id}", headers=ctx.b_headers)
        assert res.status_code == 403

    def test_owner_can_restore_own_quarantine_item(self, ctx):
        item_id = self._ensure_quarantine_a(ctx)["id"]
        res = ctx.client.post(f"/quarantine/{item_id}/restore", headers=ctx.a_headers)
        assert res.status_code == 200

    def test_owner_can_delete_own_quarantine_item(self, ctx):
        item_id = self._ensure_quarantine_a(ctx)["id"]
        res = ctx.client.delete(f"/quarantine/{item_id}", headers=ctx.a_headers)
        assert res.status_code == 200


class TestDashboardAndHistoryIsolation:
    def test_dashboard_only_counts_own_data(self, ctx):
        a_dash = ctx.client.get("/dashboard/statistics", headers=ctx.a_headers).json()
        b_dash = ctx.client.get("/dashboard/statistics", headers=ctx.b_headers).json()

        a_scans = ctx.client.get("/scans?limit=200", headers=ctx.a_headers).json()
        b_scans = ctx.client.get("/scans?limit=200", headers=ctx.b_headers).json()
        a_files = ctx.client.get("/files?limit=200", headers=ctx.a_headers).json()
        b_files = ctx.client.get("/files?limit=200", headers=ctx.b_headers).json()

        assert a_dash["total_scans"] == a_scans["total"]
        assert b_dash["total_scans"] == b_scans["total"]
        assert a_dash["total_files"] == len(a_files)
        assert b_dash["total_files"] == len(b_files)

        a_names = {r["filename"] for r in a_dash["recent_scans"]}
        b_names = {r["filename"] for r in b_dash["recent_scans"]}
        assert "user_a_secret.txt" in a_names
        assert "user_b_secret.txt" not in a_names
        assert "user_b_secret.txt" in b_names
        assert "user_a_secret.txt" not in b_names

    def test_logs_are_scoped(self, ctx):
        a_logs = ctx.client.get("/logs?limit=200", headers=ctx.a_headers).json()["logs"]
        b_logs = ctx.client.get("/logs?limit=200", headers=ctx.b_headers).json()["logs"]

        assert a_logs and b_logs
        assert all(l["user_id"] == ctx.a_id for l in a_logs)
        assert all(l["user_id"] == ctx.b_id for l in b_logs)

    def test_hash_lookup_does_not_leak_foreign_files(self, ctx):
        foreign_hash = ctx.file_b["sha256"]
        res = ctx.client.post(
            "/hash-lookup/lookup", json={"hashes": [foreign_hash]}, headers=ctx.a_headers
        )
        assert res.status_code == 200
        result = res.json()["results"][0]
        assert result["found_locally"] is False
        assert result["local_scan"] is None

    def test_export_is_scoped(self, ctx):
        res = ctx.client.get("/export/scans/csv", headers=ctx.a_headers)
        assert res.status_code == 200
        body = res.text
        assert "user_a_secret.txt" in body
        assert "user_b_secret.txt" not in body

    def test_antivirus_history_is_scoped(self, ctx):
        res = ctx.client.post(
            "/antivirus/scan-shared",
            files={"file": ("a_shared.txt", b"SHARED_A_CONTENT", "text/plain")},
            headers=ctx.a_headers,
        )
        assert res.status_code == 200, res.text

        a_hist = ctx.client.get("/antivirus/scan-history", headers=ctx.a_headers).json()["history"]
        b_hist = ctx.client.get("/antivirus/scan-history", headers=ctx.b_headers).json()["history"]

        assert all(h.get("user_id") == ctx.a_id for h in a_hist)
        assert all(h.get("user_id") == ctx.b_id for h in b_hist)
        assert "a_shared.txt" not in {h.get("filename") for h in b_hist}


class TestWebSocketIsolation:
    def test_scan_events_are_routed_to_owner_only(self):
        class FakeWS:
            def __init__(self):
                self.messages = []

            async def accept(self):
                pass

            async def send_text(self, message):
                self.messages.append(message)

        async def run():
            mgr = ConnectionManager()
            ws_a, ws_b = FakeWS(), FakeWS()
            await mgr.connect(ws_a, 101)
            await mgr.connect(ws_b, 202)

            await mgr.broadcast_scan_result({"filename": "a_secret.txt"}, user_id=101)
            await mgr.broadcast_scan_result({"filename": "b_secret.txt"}, user_id=202)
            await mgr.broadcast_notification({"title": "A alert"}, user_id=101)
            await mgr.broadcast_health_update({"cpu": 1})

            await mgr.disconnect(ws_a, 101)
            await mgr.disconnect(ws_b, 202)
            return ws_a.messages, ws_b.messages

        a_msgs, b_msgs = asyncio.run(run())

        assert any("a_secret.txt" in m for m in a_msgs)
        assert not any("b_secret.txt" in m for m in a_msgs)
        assert any("b_secret.txt" in m for m in b_msgs)
        assert not any("a_secret.txt" in m for m in b_msgs)

        assert any("A alert" in m for m in a_msgs)
        assert not any("A alert" in m for m in b_msgs)

        assert any("health_update" in m for m in a_msgs)
        assert any("health_update" in m for m in b_msgs)

    def test_websocket_requires_valid_token(self, ctx):
        with pytest.raises(Exception):
            with ctx.client.websocket_connect("/ws"):
                pass

        with pytest.raises(Exception):
            with ctx.client.websocket_connect("/ws?token=not.a.valid.token"):
                pass

    def test_connected_message_carries_own_user_id(self, ctx):
        token_a = ctx.a_headers["Authorization"].split(" ", 1)[1]
        with ctx.client.websocket_connect(f"/ws?token={token_a}") as ws:
            first = ws.receive_json()
            assert first["type"] == "connected"
            assert first["data"]["user_id"] == ctx.a_id

    def test_live_scan_events_only_reach_their_owner(self, ctx):
        token_a = ctx.a_headers["Authorization"].split(" ", 1)[1]
        token_b = ctx.b_headers["Authorization"].split(" ", 1)[1]

        collected = {"a": [], "b": []}
        stop = threading.Event()

        def reader(session, key):
            while not stop.is_set():
                try:
                    collected[key].append(session.receive_json())
                except Exception:
                    return

        with ctx.client.websocket_connect(f"/ws?token={token_a}") as ws_a, \
                ctx.client.websocket_connect(f"/ws?token={token_b}") as ws_b:
            collected["a"].append(ws_a.receive_json())
            collected["b"].append(ws_b.receive_json())

            threads = [
                threading.Thread(target=reader, args=(ws_a, "a"), daemon=True),
                threading.Thread(target=reader, args=(ws_b, "b"), daemon=True),
            ]
            for t in threads:
                t.start()

            marker = f"live_{uuid.uuid4().hex[:8]}.txt"
            res = ctx.client.post(
                "/antivirus/scan-shared",
                files={"file": (marker, b"LIVE_SCAN_CONTENT", "text/plain")},
                headers=ctx.a_headers,
            )
            assert res.status_code == 200, res.text

            deadline = time.time() + 15
            while time.time() < deadline:
                if any(marker in str(m) for m in collected["a"]):
                    break
                time.sleep(0.1)

            stop.set()
            for t in threads:
                t.join(timeout=5)

        a_text = str(collected["a"])
        b_text = str(collected["b"])
        assert marker in a_text, "owner did not receive their own scan event"
        assert marker not in b_text, "foreign user received someone else's scan event"
