import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'email-monitor-store-'));
process.env.MAX_STORED_EMAILS = '10';
const { EmailStore } = await import('../server/store.js');
const { summarize } = await import('../server/parser.js');

let seq = 0;

/** Each test starts with an empty on-disk store (DATA_DIR is temp + isolated). */
function fresh() {
  fs.rmSync(path.join(process.env.DATA_DIR, 'emails.json'), { force: true });
  return new EmailStore();
}

function makeEmail(overrides = {}) {
  seq += 1;
  return {
    id: `id-${seq}`,
    uid: seq,
    messageId: `<msg-${seq}@test>`,
    folder: 'INBOX',
    from: { name: 'Sender', address: `sender${seq}@example.com` },
    to: [{ name: '', address: 'monitor@example.com' }],
    receiver: 'monitor@example.com',
    subject: `Subject ${seq}`,
    date: new Date(2026, 8, 15, 10, 0, seq).toISOString(),
    receivedAt: new Date(2026, 8, 15, 10, 0, seq).toISOString(),
    text: `body content ${seq}`,
    html: '<p>html</p>',
    hasHtml: true,
    preview: `body content ${seq}`,
    attachments: [],
    links: [],
    size: 1000 + seq,
    ...overrides,
  };
}

test('adds emails, counts them and tracks the newest uid', () => {
  const store = fresh();
  assert.equal(store.add(makeEmail()), true);
  assert.equal(store.add(makeEmail()), true);
  assert.equal(store.count(), 2);
  assert.equal(store.getLastUid(), 2);
});

test('duplicate messageId or uid is rejected', () => {
  const store = fresh();
  const a = makeEmail({ uid: 100, messageId: '<dup@test>' });
  assert.equal(store.add(a), true);
  assert.equal(store.add({ ...makeEmail({ uid: 101 }), messageId: '<dup@test>' }), false);
  assert.equal(store.add({ ...makeEmail({ messageId: '<other@test>' }), uid: 100 }), false);
  assert.equal(store.count(), 1);
});

test('list returns newest first and keeps total beyond the storage cap', () => {
  const store = fresh();
  for (let i = 0; i < 15; i += 1) store.add(makeEmail());
  assert.equal(store.storedCount(), 10, 'storage is capped at MAX_STORED_EMAILS');
  assert.equal(store.count(), 15, 'all-time total keeps counting');
  const list = store.list(50, 0);
  assert.equal(list.length, 10);
  assert.equal(list[0].subject, `Subject ${seq}`, 'newest first');
  const page = store.list(5, 5);
  assert.equal(page.length, 5);
  assert.notEqual(page[0].id, list[0].id);
});

test('get returns the full email by id', () => {
  const store = fresh();
  const email = makeEmail();
  store.add(email);
  assert.equal(store.get(email.id).text, email.text);
  assert.equal(store.get('missing-id'), null);
});

test('data persists to disk and reloads', () => {
  const store = fresh();
  const email = makeEmail();
  store.add(email);
  const file = path.join(process.env.DATA_DIR, 'emails.json');
  assert.ok(fs.existsSync(file));
  const reloaded = new EmailStore();
  assert.equal(reloaded.get(email.id).subject, email.subject);
  assert.equal(reloaded.getLastUid(), store.getLastUid());
});

test('summarize used for list payloads contains no body text', () => {
  const store = fresh();
  const email = makeEmail();
  store.add(email);
  const summary = summarize(store.list(1, 0)[0]);
  assert.equal(summary.text, undefined);
  assert.equal(summary.html, undefined);
  assert.equal(summary.subject, email.subject);
});
