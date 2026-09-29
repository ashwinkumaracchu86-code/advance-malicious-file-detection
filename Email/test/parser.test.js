import test from 'node:test';
import assert from 'node:assert/strict';

const { parseRawEmail, summarize } = await import('../server/parser.js');

const CRLF = '\r\n';
const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
const PDF_B64 = 'JVBERi0xLjQKJcTl8uXrp/Og0MTGCg==';

function encodeWord(text) {
  return `=?utf-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`;
}

/** Build a raw RFC822 message. */
function buildMime({ from, to, subject, date, text = '', html = '', attachments = [] }) {
  const plainSubject = /^[A-Za-z0-9 :.,!()'@+-]+$/.test(subject);
  const headers = [
    `From: ${from.name ? `${encodeWord(from.name)} <${from.address}>` : from.address}`,
    `To: <${to}>`,
    `Subject: ${plainSubject ? subject : encodeWord(subject)}`,
    `Date: ${date}`,
    `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@test.local>`,
    'MIME-Version: 1.0',
  ];

  if (!attachments.length && !html) {
    return `${headers.join(CRLF)}${CRLF}${CRLF}${text}${CRLF}`;
  }

  const mixedBoundary = `----mixed_${Math.random().toString(36).slice(2)}`;
  const parts = [`${CRLF}--${mixedBoundary}${CRLF}`];

  if (html || (text && attachments.length)) {
    const altBoundary = `----alt_${Math.random().toString(36).slice(2)}`;
    parts.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"${CRLF}${CRLF}`);
    parts.push(`--${altBoundary}${CRLF}Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}${text}${CRLF}`);
    if (html) parts.push(`--${altBoundary}${CRLF}Content-Type: text/html; charset=utf-8${CRLF}${CRLF}${html}${CRLF}`);
    parts.push(`--${altBoundary}--${CRLF}`);
  } else {
    parts.push(`Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}${text}${CRLF}`);
  }

  for (const att of attachments) {
    parts.push(`--${mixedBoundary}${CRLF}`);
    parts.push(`Content-Type: ${att.contentType}; name="${att.filename}"${CRLF}`);
    parts.push(`Content-Transfer-Encoding: base64${CRLF}`);
    parts.push(`Content-Disposition: attachment; filename="${att.filename}"${CRLF}${CRLF}`);
    parts.push(`${att.data}${CRLF}`);
  }

  parts.push(`--${mixedBoundary}--${CRLF}`);
  return `${headers.join(CRLF)}${CRLF}Content-Type: multipart/mixed; boundary="${mixedBoundary}"${CRLF}${CRLF}${parts.join('')}`;
}

test('normal text email: extracts sender, receiver, subject, date and body', async () => {
  const raw = buildMime({
    from: { name: 'Alice Sender', address: 'alice@example.com' },
    to: 'monitor@example.com',
    subject: 'Hello there',
    date: 'Tue, 15 Sep 2026 10:30:00 +0000',
    text: 'This is a plain text message body.\nSecond line.',
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });

  assert.equal(email.from.name, 'Alice Sender');
  assert.equal(email.from.address, 'alice@example.com');
  assert.equal(email.receiver, 'monitor@example.com');
  assert.equal(email.subject, 'Hello there');
  assert.equal(new Date(email.date).toISOString(), '2026-09-15T10:30:00.000Z');
  assert.match(email.text, /plain text message body/);
  assert.equal(email.attachments.length, 0);
  assert.equal(email.links.length, 0);
  assert.ok(email.preview.includes('plain text message body'));
  assert.ok(email.messageId);
  assert.ok(email.size > 0);
});

test('encoded subject and display name are decoded', async () => {
  const raw = buildMime({
    from: { name: 'Björn Müller', address: 'bjorn@example.de' },
    to: 'monitor@example.com',
    subject: 'Überprüfung der Anfrage',
    date: 'Tue, 15 Sep 2026 11:00:00 +0000',
    text: 'Grüße',
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  assert.equal(email.from.name, 'Björn Müller');
  assert.equal(email.subject, 'Überprüfung der Anfrage');
});

test('email with a link: href and plain-text URLs are extracted and deduplicated', async () => {
  const raw = buildMime({
    from: { name: 'News', address: 'news@example.com' },
    to: 'monitor@example.com',
    subject: 'Newsletter with links',
    date: 'Tue, 15 Sep 2026 12:00:00 +0000',
    text: 'Visit https://example.com/page for more.\nAlso https://docs.example.org/guide',
    html: '<p>Visit <a href="https://example.com/page?x=1&amp;y=2">this</a>.</p><p><a href="https://docs.example.org/guide">docs</a> and <a href="mailto:someone@example.com">mail</a></p>',
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  assert.ok(email.hasHtml);
  assert.ok(email.links.includes('https://example.com/page?x=1&y=2'));
  assert.ok(email.links.includes('https://docs.example.org/guide'));
  assert.ok(email.links.every((l) => /^https?:\/\//i.test(l)));
  assert.equal(email.links.length, new Set(email.links.map((l) => l.toLowerCase())).size);
});

test('email containing an image: image attachment detected with filename, type and size', async () => {
  const raw = buildMime({
    from: { name: 'Designer', address: 'design@example.com' },
    to: 'monitor@example.com',
    subject: 'Logo attached',
    date: 'Tue, 15 Sep 2026 13:00:00 +0000',
    text: 'Please find the logo attached.',
    attachments: [{ filename: 'logo.png', contentType: 'image/png', data: PNG_B64 }],
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  assert.equal(email.attachments.length, 1);
  assert.equal(email.attachments[0].filename, 'logo.png');
  assert.equal(email.attachments[0].contentType, 'image/png');
  assert.ok(email.attachments[0].size > 0);
  assert.match(email.text, /logo attached/i);
});

test('email containing a document: pdf attachment detected', async () => {
  const raw = buildMime({
    from: { name: 'Accounting', address: 'billing@example.com' },
    to: 'monitor@example.com',
    subject: 'Invoice 2026-09',
    date: 'Tue, 15 Sep 2026 14:00:00 +0000',
    text: 'Invoice attached.',
    attachments: [{ filename: 'invoice-2026-09.pdf', contentType: 'application/pdf', data: PDF_B64 }],
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  assert.equal(email.attachments.length, 1);
  assert.equal(email.attachments[0].filename, 'invoice-2026-09.pdf');
  assert.equal(email.attachments[0].contentType, 'application/pdf');
  assert.ok(email.attachments[0].size > 0);
});

test('email with multiple attachments: all filenames, types and sizes reported', async () => {
  const raw = buildMime({
    from: { name: 'Project Team', address: 'team@example.com' },
    to: 'monitor@example.com',
    subject: 'Project files',
    date: 'Tue, 15 Sep 2026 15:00:00 +0000',
    text: 'All project files are attached.',
    html: '<p>All project files are attached. See <a href="https://portal.example.com/files">portal</a>.</p>',
    attachments: [
      { filename: 'photo.jpg', contentType: 'image/jpeg', data: PNG_B64 },
      { filename: 'report.docx', contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', data: PDF_B64 },
      { filename: 'notes.txt', contentType: 'text/plain', data: Buffer.from('hello').toString('base64') },
    ],
  });

  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  const names = email.attachments.map((a) => a.filename);
  assert.deepEqual(names, ['photo.jpg', 'report.docx', 'notes.txt']);
  assert.ok(email.attachments.every((a) => a.size > 0 && a.contentType));
  assert.ok(email.links.includes('https://portal.example.com/files'));
});

test('summarize strips heavy body fields for list payloads', async () => {
  const raw = buildMime({
    from: { name: 'Alice', address: 'alice@example.com' },
    to: 'monitor@example.com',
    subject: 'Summary check',
    date: 'Tue, 15 Sep 2026 16:00:00 +0000',
    text: 'secret body content',
  });
  const email = await parseRawEmail(raw, { monitored: 'monitor@example.com' });
  const summary = summarize(email);
  assert.equal(summary.text, undefined);
  assert.equal(summary.html, undefined);
  assert.equal(summary.subject, 'Summary check');
  assert.equal(summary.from.address, 'alice@example.com');
});
