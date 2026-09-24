# Part 2 Report — Email Security Module (Backend)

Date: 2026-09-23
Scope: Backend only. Frontend wiring is Part 3 (not started).

## 1. Summary

Made the Gmail/IMAP email monitoring real and secure, reusing the existing
scanner (`backend/app/scanner/file_analyzer.py`), quarantine
(`backend/app/services/quarantine_service.py`) and risk engine
(`backend/app/services/email_risk_engine.py`). No second scanner/quarantine
was created. No existing modules (login, dashboard, scanner, quarantine,
reports, antivirus, sandbox, firewall, USB, network share, threat intel,
admin, settings) were modified.

## 2. Files Changed

| File | Change |
|---|---|
| `backend/app/services/email_monitor_service.py` | Fixed critical runtime bugs (see §5) |
| `backend/app/models/email_models.py` | (prior edit) added `spf/dkim/dmarc/scan_source` on `EmailRecord`, status/heartbeat/counter columns on `EmailMonitoringConfig`, new `EmailProcessedUID` table |
| `backend/app/main.py` | Added `_ensure_email_schema_columns()` (non-destructive ALTER TABLE / table create) + called in lifespan; fixed SQLAlchemy 2.x `Engine.execute` bug; `EmailProcessedUID` imported |
| `backend/app/routes/email_security.py` | Rewrote monitoring config/status endpoints, added `test-connection`, richer email list filters + detail fields, reuses full scanner in `/scan` |
| `backend/email_worker.py` | NEW — Render Background Worker entrypoint |
| `.env.example`, `backend/.env.example` | Docs for `ENCRYPTION_KEY`, `ALLOWED_ORIGINS` (incl. GitHub Pages), IMAP/email quarantine env |

## 3. APIs (updated / added)

- `GET /email-security/monitoring/config` — now returns full real state incl.
  `last_success_check`, `last_error`, `connection_status`, `last_heartbeat`,
  counters. **Never returns the password.** New installs return `{configured: False}`.
- `POST /email-security/monitoring/config` — encrypts the password with
  `encrypt_value()` (XOR+base64, `enc:` prefix) unless already encrypted; empty
  password keeps the stored one; in-memory worker config updated **without**
  passing plaintext password.
- `POST /email-security/monitoring/test-connection` — performs a REAL IMAP
  connect using the saved config (decrypts internally) or an explicit body
  config. Returns `status: "CONNECTED"|"FAILED"` (or `NOT_CONFIGURED`) plus the
  host/port error details. Never logs or returns the password.
- `POST /email-security/monitoring/start` — validates config, sets `is_active`,
  loads config into the worker (encrypted password; worker decrypts), starts the
  monitor thread, writes an AuditLog, returns `worker_running`.
- `POST /email-security/monitoring/stop` — deactivates + removes config from the
  worker, AuditLog.
- `GET /email-security/monitoring/status` — real state backed by DB + worker:
  `monitoring_status` (`active|starting|error|stopped|NOT_CONFIGURED`),
  `connection_status`, `worker_running`, `heartbeat_stale`
  (`now - last_heartbeat > 5 * max(10, polling_interval)`), check timestamps,
  counters. Never exposes credentials.
- `GET /email-security/emails` — added filters: `recipient`, `message_id`,
  `spf`, `dkim`, `dmarc`, `is_quarantined`, `has_attachments`, `min_risk`,
  `max_risk`, `date_from`, `date_to`, and `search` now also matches filename /
  SHA-256 via `email_attachments`. Response includes the new auth fields.
- `GET /email-security/emails/{id}` — detail now includes `message_id`,
  `reply_to`, `return_path`, `scan_source`, `spf/dkim/dmarc`, and per-attachment
  `entropy`, `detected_mime`, `is_mime_mismatch`, `is_quarantined`,
  `quarantine_path`, `clamav_*`.
- `POST /email-security/scan` — now runs attachments through the full
  scanner-backed `analyze_attachment()` (hash, entropy, MIME detection/mismatch,
  ClamAV if enabled), stores the richer fields, and sets `spf/dkim/dmarc` from
  real headers + `scan_source="upload"`. Removed the old local, weaker analyzer.

## 4. Database Changes (additive only, safe on existing DB)

`_ensure_email_schema_columns()` (main.py) runs on startup and adds, only if
missing:
- `email_records`: `spf`, `dkim`, `dmarc`, `scan_source`
- `email_monitoring_config`: `last_success_check`, `last_error`,
  `connection_status`, `last_heartbeat`, `emails_checked`, `threats_detected`,
  `quarantined_attachments`
- Creates `email_processed_uids` (`config_id+folder+uid` unique) for dedupe.

Verified against a copy of the **production live DB**
(`backend/malicious_detection.db`): all four `email_records` columns and seven
`email_monitoring_config` columns were missing and were added by the migration;
`email_processed_uids` was created. The legacy extra `email_attachments.yara_matches`
column is ignored by the model (harmless) and `quarantine_items.file_id NOT NULL`
is handled by the FileRecord fix below.

## 5. Critical Bug Fixes (email_monitor_service.py)

1. **`hashlib` missing import** — `NameError` on the max-attachment-size branch.
   Added `import hashlib`.
2. **`aa.get("_data")` never set** — attachment bytes were never passed to the
   base64/`_data` logic, so HTML-scanning / body linkage was broken. `analyze_attachment`
   now always includes `"_data": data` (internal; excluded from serialized output).
3. **Unsafe asyncio from a background thread** — `asyncio.get_event_loop().run_until_complete()`
   in the IMAP monitor thread. Replaced with loop capture at registration time
   (`register_ws` stores `asyncio.get_running_loop()`) and
   `asyncio.run_coroutine_threadsafe(...)`, dropping dead websockets via a done-callback.
4. **Quarantine silently failing** — `quarantine_file()` requires a non-NULL
   `quarantine_items.file_id`; with no matching `File` row it raised
   `sqlite3.IntegrityError` and returned `None` (file physically moved, no DB row).
   Fix: `_quarantine_via_file_record()` writes the attachment to a temp file,
   creates a `File` record (`file_path=temp path`), then calls the **existing**
   `quarantine_file()` so the attachment links to `file_id` and lands in
   `quarantine_items`. Attachments are never executed.

## 6. Worker / Deployment (Render)

- In-process monitor thread starts via `POST /email-security/monitoring/start`.
- NEW `backend/email_worker.py` for a Render Background Worker:
  `python email_worker.py`. Loads active configs from DB, starts the monitor
  (heartbeats + connection status + counters persisted every cycle). Dedupe
  across processes uses `email_processed_uids`.
- No `render.yaml`/`Procfile` added per scope constraints — the existing
  auto-deploy from `main` continues; you may add a Background Worker service
  pointing at `python email_worker.py`.

## 7. Security Improvements

- Passwords encrypted at rest (`enc:` + XOR/base64 via `encrypt_value`); never
  returned by any endpoint; never passed in plaintext through the in-memory
  worker update path; worker decrypts only at connect time.
- `GET /monitoring/config`, `status`, and `test-connection` responses contain
  no password field.
- Monitoring status reflects genuine state; heartbeat staleness is detectable.
- Existing pre-deployed config row on the live DB (`imap_host='993'`, plaintext
  password `163gpt`, provider `custom`) is junk; users should re-save config.

## 8. Tests + Results

- `py_compile` clean for all changed modules; full app import clean (25 routes).
- Endpoint smoke test (temp DB, real uvicorn, `requests`):
  register → login → save config → get config (no password leak) →
  password stored as `enc:` → start (worker_running) → status (real state, no
  password leak) → test-connection (uses saved config; status CONNECTED/FAILED;
  no leak) → stop → list emails → scan a crafted phishing `.eml` (returns
  email_id, attachments, sender_analysis, risk assessment) → stats.
  Result: **ALL_PASS**.
- Live-DB schema migration test on a copy of production DB: **all columns added,
  `email_processed_uids` created** — pass.

## 9. Remaining Issues / Notes

- No valid Gmail/IMAP credentials available → real end-to-end polling could not
  be exercised; test-connection against a fake host only verifies the FAILED
  path plumbing. Use a real account + App Password to validate a full poll.
- Live DB already contains one misconfigured monitoring row for user 1; it will
  surface as `error` state until the user saves a correct config.
- `starlette.testclient` requires `httpx2` in this venv, so tests use a spawned
  uvicorn server instead.
- Render production base is `https://advance-malicious-file-detection-3.onrender.com`.

## 10. Next Step (Part 3 — not started)

Frontend: `frontend/src/services/api.js`, `EmailLiveMonitorPage.jsx`,
`App.jsx`/`Sidebar.jsx` wiring for monitoring config/test/start/stop/status,
live email list filters, and the WebSocket event feed.