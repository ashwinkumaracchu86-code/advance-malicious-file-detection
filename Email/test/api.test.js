import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'email-monitor-api-'));
delete process.env.IMAP_HOST;
delete process.env.IMAP_PORT;
delete process.env.IMAP_SECURE;
delete process.env.IMAP_USER;
delete process.env.IMAP_PASS;
delete process.env.MONITORED_EMAIL;
delete process.env.DASHBOARD_PIN;

const { createApp } = await import('../server/index.js');
const { EmailStore } = await import('../server/store.js');
const { EmailMonitor } = await import('../server/monitor.js');

function makeServer({ pin = '' } = {}) {
  const store = new EmailStore();
  const monitor = new EmailMonitor(store);
  const app = createApp({ store, monitor, pin });
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      resolve({ server, store, monitor, base: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

let ctx;
let activeMonitor;

test.before(async () => {
  ctx = await makeServer();
  activeMonitor = ctx.monitor;
  // Initial state: nothing configured yet.
  await ctx.monitor.start();
});

test.after(async () => {
  await activeMonitor.stop();
  await new Promise((resolve) => ctx.server.close(resolve));
});

test('GET /api/status reports "email not configured" while no account exists', async () => {
  const res = await fetch(`${ctx.base}/api/status`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.configured, false);
  assert.equal(body.monitoring, 'inactive');
  assert.equal(body.code, 'not_configured');
  assert.match(body.message, /Email not configured/i);
  assert.equal(body.totalEmails, 0);
  assert.equal(body.mailbox, null);
});

test('POST /api/monitor/start returns the not-configured error clearly', async () => {
  const res = await fetch(`${ctx.base}/api/monitor/start`, { method: 'POST' });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(body.status.code, 'not_configured');
  assert.match(body.status.message, /Settings/i);
});

test('GET /api/emails starts empty', async () => {
  const res = await fetch(`${ctx.base}/api/emails`);
  const body = await res.json();
  assert.equal(body.total, 0);
  assert.deepEqual(body.emails, []);
});

test('GET /api/emails/:id unknown id returns 404', async () => {
  const res = await fetch(`${ctx.base}/api/emails/does-not-exist`);
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.code, 'not_found');
});

test('POST /api/settings rejects invalid input with a clear message', async () => {
  const res = await fetch(`${ctx.base}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host: '', user: 'not-an-email', port: 99999 }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.match(body.error, /required|invalid/i);
});

test('invalid JSON body returns 400, not a crash', async () => {
  const res = await fetch(`${ctx.base}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{ this is not json',
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.match(body.error, /JSON/i);
});

test('POST /api/settings saves encrypted credentials and never returns the password', async () => {
  const password = 'super-secret-app-password';
  const res = await fetch(`${ctx.base}/api/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      host: 'imap.example.test',
      port: 993,
      secure: true,
      user: 'monitor@example.com',
      monitored: 'monitor@example.com',
      pass: password,
    }),
  });
  assert.equal(res.status, 200);
  const raw = await res.text();
  assert.ok(!raw.includes(password), 'password must never appear in an API response');
  const body = JSON.parse(raw);
  assert.equal(body.ok, true);
  assert.equal(body.settings.configured, true);
  assert.equal(body.settings.hasPassword, true);
  assert.equal(body.settings.pass, undefined);

  const get = await fetch(`${ctx.base}/api/settings`);
  const settings = await get.json();
  assert.equal(settings.user, 'monitor@example.com');
  assert.equal(settings.host, 'imap.example.test');
  assert.equal(settings.hasPassword, true);
  assert.ok(!JSON.stringify(settings).includes(password));

  const configFile = path.join(process.env.DATA_DIR, 'config.json');
  const onDisk = fs.readFileSync(configFile, 'utf8');
  assert.ok(!onDisk.includes(password), 'password must be stored encrypted on disk');
  assert.ok(onDisk.includes('passEnc'));
});

test('saved settings are encrypted at rest but usable by the config layer', async () => {
  const { getMailboxConfig } = await import('../server/config.js');
  const cfg = getMailboxConfig();
  assert.equal(cfg.configured, true);
  assert.equal(cfg.source, 'settings');
  assert.equal(cfg.pass, 'super-secret-app-password');
  assert.equal(cfg.user, 'monitor@example.com');
});

test('status now reports configured account', async () => {
  const res = await fetch(`${ctx.base}/api/status`);
  const body = await res.json();
  assert.equal(body.configured, true);
  assert.equal(body.mailbox.host, 'imap.example.test');
  assert.equal(body.mailbox.source, 'settings');
});

test('unknown API endpoint returns a clear server error shape', async () => {
  const res = await fetch(`${ctx.base}/api/nope`);
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.code, 'not_found');
  assert.match(body.error, /Server\/API error/);
});

test('dashboard page is served with security headers', async () => {
  const res = await fetch(`${ctx.base}/`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Email Monitor/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.match(res.headers.get('content-security-policy') || '', /script-src 'self'/);
});

test('PIN protection: requests without the PIN are rejected', async () => {
  const pinned = await makeServer({ pin: '4455' });
  try {
    const denied = await fetch(`${pinned.base}/api/status`);
    assert.equal(denied.status, 401);
    const deniedBody = await denied.json();
    assert.equal(deniedBody.code, 'pin_required');

    const wrong = await fetch(`${pinned.base}/api/status`, { headers: { 'x-pin': '0000' } });
    assert.equal(wrong.status, 401);

    const allowed = await fetch(`${pinned.base}/api/status`, { headers: { 'x-pin': '4455' } });
    assert.equal(allowed.status, 200);
  } finally {
    await pinned.monitor.stop();
    await new Promise((resolve) => pinned.server.close(resolve));
  }
});
