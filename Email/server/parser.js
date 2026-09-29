import { simpleParser } from 'mailparser';

const MAX_LINKS = 100;
const MAX_TEXT = 200_000;
const MAX_HTML = 500_000;

function decodeEntities(str) {
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&nbsp;/gi, ' ');
}

function collectLinks(text = '', html = '') {
  const found = [];
  const push = (url) => {
    if (!url) return;
    let u = decodeEntities(String(url).trim());
    if (!/^https?:\/\//i.test(u)) return;
    if (u.length > 2048) u = u.slice(0, 2048);
    if (!found.some((f) => f.toLowerCase() === u.toLowerCase())) found.push(u);
  };

  const hrefRe = /href\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html)) !== null) push(m[1]);

  const urlRe = /https?:\/\/[^\s<>"'()\\]+/gi;
  while ((m = urlRe.exec(text)) !== null) push(m[0]);

  return found.slice(0, MAX_LINKS);
}

function addressList(addressObject) {
  if (!addressObject) return [];
  const values = Array.isArray(addressObject.value) ? addressObject.value : [];
  return values
    .filter((v) => v && v.address)
    .map((v) => ({ name: (v.name || '').trim(), address: String(v.address).trim() }));
}

function pickReceiver(toList, ccList, monitored) {
  const candidates = [...toList, ...ccList];
  if (monitored) {
    const hit = candidates.find((c) => c.address.toLowerCase() === String(monitored).toLowerCase());
    if (hit) return hit.address;
  }
  return candidates.length ? candidates[0].address : '';
}

function toISO(value) {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

/** Parse a raw RFC822 message into the dashboard's email record. */
export async function parseRawEmail(source, { monitored = '', uid = null, folder = 'INBOX' } = {}) {
  const data = await simpleParser(source);

  const fromList = addressList(data.from);
  const toList = addressList(data.to);
  const ccList = addressList(data.cc);

  const html = typeof data.html === 'string' ? data.html : Array.isArray(data.html) ? data.html.join('\n') : '';
  const text = typeof data.text === 'string' ? data.text : '';
  const attachments = (data.attachments || []).map((a, i) => ({
    filename: a.filename || `attachment-${i + 1}`,
    contentType: a.contentType || 'application/octet-stream',
    size: Number.isFinite(a.size) ? a.size : 0,
    disposition: a.contentDisposition || '',
  }));

  const subject = (data.subject || '').trim() || '(no subject)';
  const from = fromList.length
    ? fromList[0]
    : { name: '', address: '' };

  return {
    id: null,
    uid,
    folder,
    messageId: data.messageId || null,
    from,
    to: toList,
    cc: ccList,
    receiver: pickReceiver(toList, ccList, monitored),
    subject,
    date: toISO(data.date || Date.now()),
    receivedAt: new Date().toISOString(),
    text: text.slice(0, MAX_TEXT),
    html: html.slice(0, MAX_HTML),
    hasHtml: Boolean(html),
    preview: text.replace(/\s+/g, ' ').trim().slice(0, 200),
    attachments,
    links: collectLinks(text, html),
    size: typeof source === 'string' ? Buffer.byteLength(source) : source?.length || 0,
  };
}

/** Strip heavy fields for list/realtime payloads. */
export function summarize(email) {
  if (!email) return null;
  const { text, html, ...rest } = email;
  return rest;
}
