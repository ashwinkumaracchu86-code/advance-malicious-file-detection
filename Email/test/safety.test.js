import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'email-monitor-safety-'));

const { assessEmailSafety, safetyLabel, SAFETY_STATUS } = await import('../server/safety.js');
const { parseRawEmail, summarize } = await import('../server/parser.js');
const { EmailStore } = await import('../server/store.js');

const CRLF = '\r\n';
const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

function buildMime({ from, to, subject, date, text = '', html = '', attachments = [] }) {
  const headers = [
    `From: ${from.name ? `${from.name} <${from.address}>` : from.address}`,
    `To: <${to}>`,
    `Subject: ${subject}`,
    `Date: ${date}`,
    `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@safety.test>`,
    'MIME-Version: 1.0',
  ];

  if (!attachments.length && !html) {
    return `${headers.join(CRLF)}${CRLF}${CRLF}${text}${CRLF}`;
  }

  const boundary = `----mixed_${Math.random().toString(36).slice(2)}`;
  const parts = [`${CRLF}--${boundary}${CRLF}`];

  if (html) {
    const alt = `----alt_${Math.random().toString(36).slice(2)}`;
    parts.push(`Content-Type: multipart/alternative; boundary="${alt}"${CRLF}${CRLF}`);
    parts.push(`--${alt}${CRLF}Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}${text}${CRLF}`);
    parts.push(`--${alt}${CRLF}Content-Type: text/html; charset=utf-8${CRLF}${CRLF}${html}${CRLF}`);
    parts.push(`--${alt}--${CRLF}`);
  } else {
    parts.push(`Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}${text}${CRLF}`);
  }

  for (const att of attachments) {
    parts.push(`--${boundary}${CRLF}`);
    parts.push(`Content-Type: ${att.contentType}; name="${att.filename}"${CRLF}`);
    parts.push('Content-Transfer-Encoding: base64' + CRLF);
    parts.push(`Content-Disposition: attachment; filename="${att.filename}"${CRLF}${CRLF}`);
    parts.push(`${att.data}${CRLF}`);
  }

  parts.push(`--${boundary}--${CRLF}`);
  return `${headers.join(CRLF)}${CRLF}Content-Type: multipart/mixed; boundary="${boundary}"${CRLF}${CRLF}${parts.join('')}`;
}

function baseEmail(overrides = {}) {
  return {
    from: { name: 'Alice Sender', address: 'alice@example.com' },
    to: [{ name: '', address: 'monitor@example.com' }],
    receiver: 'monitor@example.com',
    subject: 'Lunch tomorrow?',
    date: new Date('2026-09-25T10:00:00Z').toISOString(),
    receivedAt: new Date('2026-09-25T10:00:01Z').toISOString(),
    text: 'Hi, lunch at 1pm works for me.',
    preview: 'Hi, lunch at 1pm works for me.',
    attachments: [],
    links: [],
    ...overrides,
  };
}

test('a normal email is reported SAFE with a matching label', () => {
  const result = assessEmailSafety(baseEmail());
  assert.equal(result.status, SAFETY_STATUS.SAFE);
  assert.equal(result.label, '\u{1F7E2} SAFE');
  assert.equal(safetyLabel('safe'), result.label);
});

test('an executable attachment makes the email DANGEROUS', () => {
  const result = assessEmailSafety(
    baseEmail({
      subject: 'Invoice',
      attachments: [{ filename: 'invoice.exe', contentType: 'application/octet-stream', size: 2048 }],
    }),
  );
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
  assert.ok(result.reasons.length > 0);
});

test('a double extension attachment makes the email DANGEROUS', () => {
  const result = assessEmailSafety(
    baseEmail({
      attachments: [{ filename: 'photo.jpg.exe', contentType: 'image/jpeg', size: 1024 }],
    }),
  );
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
});

test('a normal image attachment is still SAFE', () => {
  const result = assessEmailSafety(
    baseEmail({
      subject: 'Holiday photo',
      attachments: [{ filename: 'photo.jpg', contentType: 'image/jpeg', size: 4096 }],
    }),
  );
  assert.equal(result.status, SAFETY_STATUS.SAFE);
});

test('phishing wording combined with a link makes the email DANGEROUS', () => {
  const result = assessEmailSafety(
    baseEmail({
      subject: 'Verify your account',
      text: 'Click the link below to verify your account.',
      links: ['https://accounts.example.com/verify?id=1'],
    }),
  );
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
});

test('a link pointing at a raw IP address makes the email DANGEROUS', () => {
  const result = assessEmailSafety(baseEmail({ links: ['http://192.168.10.5/update/login'] }));
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
});

test('brand impersonation from a free mail account makes the email DANGEROUS', () => {
  const result = assessEmailSafety(
    baseEmail({ from: { name: 'PayPal Security', address: 'secure.alerts2026@gmail.com' } }),
  );
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
});

test('an attachment that cannot be inspected is UNKNOWN, never SAFE', () => {
  const result = assessEmailSafety(
    baseEmail({
      subject: 'Files',
      attachments: [{ filename: 'archive.zip', contentType: 'application/zip', size: 9000 }],
    }),
  );
  assert.equal(result.status, SAFETY_STATUS.UNKNOWN);
  assert.equal(result.label, '\u26AA UNKNOWN');
});

test('a missing sender address is not reported SAFE', () => {
  const result = assessEmailSafety(baseEmail({ from: { name: '', address: '' } }));
  assert.equal(result.status, SAFETY_STATUS.DANGEROUS);
});

test('an existing malware scan result is honoured', () => {
  const infected = assessEmailSafety(baseEmail({ malwareScan: { infected: true, engine: 'clamav' } }));
  assert.equal(infected.status, SAFETY_STATUS.DANGEROUS);

  const clean = assessEmailSafety(baseEmail({ scanResult: 'clean' }));
  assert.equal(clean.status, SAFETY_STATUS.SAFE);

  const errored = assessEmailSafety(baseEmail({ scan: { error: 'scanner timeout' } }));
  assert.equal(errored.status, SAFETY_STATUS.UNKNOWN);
});

test('a null/non-object email degrades to UNKNOWN', () => {
  assert.equal(assessEmailSafety(null).status, SAFETY_STATUS.UNKNOWN);
  assert.equal(assessEmailSafety(undefined).status, SAFETY_STATUS.UNKNOWN);
  assert.equal(assessEmailSafety('nope').status, SAFETY_STATUS.UNKNOWN);
});

test('parsed incoming email carries a safety status into list payloads', async () => {
  const raw = buildMime({
    from: { name: 'Alice Sender', address: 'alice@example.com' },
    to: 'monitor@example.com',
    subject: 'Hello there',
    date: 'Fri, 25 Sep 2026 10:30:00 +0000',
    text: 'This is a plain text message body.',
  });
  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  email.safety = assessEmailSafety(email);

  assert.equal(email.safety.status, 'safe');
  const summary = summarize(email);
  assert.equal(summary.text, undefined);
  assert.equal(summary.safety.status, 'safe');
  assert.equal(summary.safety.label, '\u{1F7E2} SAFE');
});

test('parsed email with a dangerous attachment is reported DANGEROUS end to end', async () => {
  const raw = buildMime({
    from: { name: 'unknown', address: 'unknown@example.com' },
    to: 'monitor@example.com',
    subject: 'Verify your account',
    date: 'Fri, 25 Sep 2026 11:00:00 +0000',
    text: 'Open the attachment to continue.',
    attachments: [{ filename: 'invoice.exe', contentType: 'application/octet-stream', data: 'TVqQAAMAAAAEAAAA' }],
  });
  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  email.safety = assessEmailSafety(email);
  assert.equal(email.safety.status, 'dangerous');
});

test('the store fills in a safety status for records saved without one', () => {
  const file = path.join(process.env.DATA_DIR, 'emails.json');
  fs.rmSync(file, { force: true });
  const legacy = baseEmail({ id: 'legacy-1', uid: 1, messageId: '<legacy@test>' });
  fs.writeFileSync(
    file,
    JSON.stringify({ version: 1, total: 1, lastUid: 1, emails: [legacy] }),
    'utf8',
  );

  const store = new EmailStore();
  const stored = store.get('legacy-1');
  assert.equal(stored.safety.status, 'safe');
  assert.equal(stored.safety.label, '\u{1F7E2} SAFE');
});

test('the store adds a safety status to newly stored emails', () => {
  fs.rmSync(path.join(process.env.DATA_DIR, 'emails.json'), { force: true });
  const store = new EmailStore();
  const email = baseEmail({ id: 'new-1', uid: 5, messageId: '<new@test>' });
  assert.equal(store.add(email), true);
  assert.equal(store.get('new-1').safety.status, 'safe');
});
