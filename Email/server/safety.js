/**
 * Email safety status.
 *
 * Analyses an already-parsed email record (see parser.js) and returns one of:
 *   safe      -> 🟢 SAFE
 *   dangerous -> 🔴 DANGEROUS
 *   unknown   -> ⚪ UNKNOWN  (never claim SAFE when the result cannot be determined)
 *
 * The analysis is deterministic, offline and never opens or executes attachments:
 * it only inspects metadata (sender, subject/body wording, links, attachment names
 * and content types) plus any malware scan result already attached to the record.
 */

const SAFE = 'safe';
const DANGEROUS = 'dangerous';
const UNKNOWN = 'unknown';

export const SAFETY_STATUS = { SAFE, DANGEROUS, UNKNOWN };

export const SAFETY_LABELS = {
  [SAFE]: '\u{1F7E2} SAFE',
  [DANGEROUS]: '\u{1F534} DANGEROUS',
  [UNKNOWN]: '\u26AA UNKNOWN',
};

export function safetyLabel(status) {
  return SAFETY_LABELS[status] || SAFETY_LABELS[UNKNOWN];
}

// Executables, scripts, shortcuts, disk images and macro-enabled documents.
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'ps1', 'psm1', 'msi', 'msp', 'msix', 'appx', 'dll', 'sys', 'cpl', 'hta', 'jar',
  'reg', 'lnk', 'url', 'iso', 'img', 'vhd', 'vhdx', 'apk', 'dex', 'sh', 'run',
  'deb', 'rpm', 'gadget', 'chm', 'ws', 'application', 'outlook', 'docm', 'dotm',
  'xlsm', 'xltm', 'xlam', 'pptm', 'ppsm', 'potm', 'bin', 'elf', 'so', 'dylib',
]);

// Document/media types a normal email legitimately carries - contents are never executed here.
const SAFE_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic', 'tif', 'tiff',
  'pdf', 'txt', 'csv', 'rtf', 'md', 'log', 'doc', 'docx', 'xls', 'xlsx',
  'ppt', 'pptx', 'pps', 'odt', 'ods', 'odp', 'ics', 'vcf',
  'mp3', 'mp4', 'm4a', 'wav', 'flac', 'ogg', 'mov', 'avi', 'mkv', 'webm',
]);

// Extensions attackers hide behind when they append a second, dangerous extension.
const DECOY_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'rtf',
  'jpg', 'jpeg', 'png', 'gif', 'html', 'htm', 'mp3', 'mp4', 'zip',
]);

const DANGEROUS_CONTENT_TYPES = new Set([
  'application/x-msdownload', 'application/x-msdos-program', 'application/x-executable',
  'application/x-dosexec', 'application/x-exe', 'application/x-ms-shortcut',
  'application/vnd.microsoft.portable-executable', 'application/x-bat', 'application/x-sh',
  'application/x-shellscript', 'application/x-msi', 'application/java-archive',
  'application/x-java-archive', 'application/x-apple-diskimage', 'application/x-cd-image',
  'application/x-iso9660-image',
]);

const SAFE_CONTENT_TYPES = new Set([
  'application/pdf', 'application/rtf', 'application/msword',
  'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet',
  'application/vnd.oasis.opendocument.presentation', 'text/plain', 'text/csv',
  'text/rtf', 'audio/mpeg', 'audio/mp4', 'audio/wav', 'audio/x-wav',
  'video/mp4', 'video/quicktime', 'video/webm',
]);

const SAFE_CONTENT_TYPE_PREFIXES = ['image/', 'audio/', 'video/'];

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'cutt.ly', 'cutt.us',
  'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 'v.gd', 'buff.ly', 'lnkd.in',
  'bl.ink', 'soo.gd', 'clk.sh',
]);

const FREEMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com', 'outlook.com',
  'live.com', 'msn.com', 'icloud.com', 'me.com', 'aol.com', 'protonmail.com', 'proton.me',
  'gmx.com', 'gmx.de', 'mail.com', 'zoho.com', 'yandex.com', 'mail.ru', 'inbox.com',
  'aim.com', 'qq.com', '163.com', '126.com', 'rediffmail.com', 'rocketmail.com',
]);

// Only brand names that never appear in an ordinary personal display name.
const BRAND_WORDS = [
  'paypal', 'apple', 'icloud', 'microsoft', 'office365', 'google', 'gmail', 'amazon',
  'netflix', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'github', 'dropbox',
  'adobe', 'spotify', 'steam', 'binance', 'coinbase', 'chase', 'citibank', 'barclays',
  'hsbc', 'revolut', 'dhl', 'fedex', 'usps', 'venmo', 'cashapp', 'stripe',
];

const PHISHING_PHRASES = [
  /\bverify\s+(?:your|this)\s+(?:account|identity|email|password|mailbox)\b/i,
  /\baccount\s+(?:will\s+be|has\s+been|is\s+being)\s+(?:suspended|locked|limited|closed|deactivated)\b/i,
  /\bunusual\s+(?:sign[-\s]?in|login)\s+(?:attempt|activity)\b/i,
  /\bconfirm\s+your\s+(?:password|account|identity|payment|details|information)\b/i,
  /\b(?:password|credentials?)\s+(?:expires|expired|reset|required|must\s+be\s+(?:updated|changed))\b/i,
  /\breactivate\s+your\s+(?:account|mailbox)\b/i,
  /\bimmediate\s+action\s+required\b/i,
  /\byou\s+(?:have\s+)?won\b/i,
  /\bclaim\s+your\s+(?:prize|reward|bonus|gift)\b/i,
  /\bfinal\s+notice\b/i,
  /\bupdate\s+your\s+(?:payment|billing|account)\s+(?:details|information)\b/i,
  /\bunauthori[sz]ed\s+(?:access|sign[-\s]?in)\b/i,
];

const EMAIL_ADDRESS_IN_NAME_RE = /[^\s<>()\[\]]+@[^\s<>()\[\]]+\.[^\s<>()\[\]]+/;
const VALID_ADDRESS_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const OBFUSCATION_RE = /[\u0000-\u001F\u007F\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

function normalizeStatus(status) {
  return status === SAFE || status === DANGEROUS ? status : UNKNOWN;
}

function makeResult(status, reasons = []) {
  const normalized = normalizeStatus(status);
  const unique = [...new Set(reasons.filter(Boolean).map((r) => String(r).trim()))].slice(0, 8);
  return { status: normalized, label: safetyLabel(normalized), reasons: unique };
}

function extensionOf(name) {
  const clean = String(name || '').split(/[\\/]/).pop() || '';
  const idx = clean.lastIndexOf('.');
  if (idx <= 0 || idx === clean.length - 1) return '';
  return clean.slice(idx + 1).toLowerCase();
}

function baseDomain(host) {
  const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : parts.join('.');
}

function isIpLiteral(host) {
  const h = String(host || '').replace(/^\[|\]$/g, '');
  if (IPV4_RE.test(h)) return h.split('.').every((p) => Number(p) <= 255);
  return h.includes(':');
}

// --- Individual checks -------------------------------------------------------

function checkSender(email, findings) {
  const from = email.from || {};
  const address = String(from.address || '').trim();
  const name = String(from.name || '').trim();

  if (!address) {
    findings.push({ level: 'suspicious', code: 'missing_sender', message: 'Sender address is missing.' });
    return;
  }
  if (!VALID_ADDRESS_RE.test(address)) {
    findings.push({ level: 'suspicious', code: 'invalid_sender', message: 'Sender address looks invalid.' });
    return;
  }

  const domain = address.split('@')[1].toLowerCase();

  if (IPV4_RE.test(domain)) {
    findings.push({ level: 'suspicious', code: 'ip_sender', message: 'Sender domain is a raw IP address.' });
  }
  if (domain.includes('xn--')) {
    findings.push({ level: 'suspicious', code: 'punycode_sender', message: 'Sender domain uses an internationalised (punycode) name.' });
  }

  const embedded = (name.match(EMAIL_ADDRESS_IN_NAME_RE) || [])[0];
  if (embedded && embedded.toLowerCase() !== address.toLowerCase()) {
    findings.push({
      level: 'suspicious',
      code: 'spoofed_display_name',
      message: `Display name shows a different address (${embedded}).`,
    });
  }

  const freemail = FREEMAIL_DOMAINS.has(domain) || FREEMAIL_DOMAINS.has(baseDomain(domain));
  if (freemail) {
    const lowerName = name.toLowerCase();
    const brand = BRAND_WORDS.find((w) => lowerName.includes(w));
    if (brand) {
      findings.push({
        level: 'suspicious',
        code: 'brand_impersonation',
        message: `Display name claims "${brand}" but the sender is a free mail account.`,
      });
    }
  }
}

function checkAttachment(att, findings) {
  const rawName = String((att && att.filename) || '');
  const cleanName = (rawName.split(/[\\/]/).pop() || rawName).trim().toLowerCase().replace(/[.\s]+$/, '');
  const ext = extensionOf(cleanName);
  const contentType = String((att && att.contentType) || '').toLowerCase().split(';')[0].trim();
  let unresolved = false;

  if (rawName && OBFUSCATION_RE.test(rawName)) {
    findings.push({
      level: 'malicious',
      code: 'obfuscated_filename',
      message: `Attachment name "${cleanName || rawName}" uses hidden control characters.`,
    });
  }

  if (ext && DANGEROUS_EXTENSIONS.has(ext)) {
    findings.push({
      level: 'malicious',
      code: 'dangerous_attachment',
      message: `Attachment "${cleanName || rawName}" has a dangerous .${ext} type.`,
    });
  }

  if (contentType && DANGEROUS_CONTENT_TYPES.has(contentType)) {
    findings.push({
      level: 'malicious',
      code: 'dangerous_attachment_type',
      message: `Attachment "${cleanName || rawName}" is sent as ${contentType}.`,
    });
  }

  const parts = cleanName.split('.');
  if (parts.length >= 2) {
    const last = parts[parts.length - 1];
    const decoy = parts[parts.length - 2];
    if (DANGEROUS_EXTENSIONS.has(last) && DECOY_EXTENSIONS.has(decoy)) {
      findings.push({
        level: 'malicious',
        code: 'double_extension',
        message: `Attachment "${cleanName}" hides a .${last} file behind a .${decoy} name.`,
      });
    }
  }

  const safeByExt = ext && SAFE_EXTENSIONS.has(ext);
  const safeByType =
    contentType &&
    (SAFE_CONTENT_TYPE_PREFIXES.some((p) => contentType.startsWith(p)) || SAFE_CONTENT_TYPES.has(contentType));

  if (!safeByExt && !safeByType) unresolved = true;
  return unresolved;
}

function checkLink(raw, findings) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    findings.push({ level: 'suspicious', code: 'malformed_url', message: 'Email contains a malformed URL.' });
    return;
  }

  const protocol = url.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    findings.push({
      level: 'malicious',
      code: 'dangerous_url_scheme',
      message: `Link uses the ${protocol} scheme.`,
    });
    return;
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) {
    findings.push({ level: 'suspicious', code: 'malformed_url', message: 'Link has no host name.' });
    return;
  }

  if (url.username || url.password) {
    findings.push({
      level: 'suspicious',
      code: 'url_userinfo_trick',
      message: `Link "${String(raw).slice(0, 80)}" hides its real destination after an @ sign.`,
    });
  }
  if (isIpLiteral(host)) {
    findings.push({ level: 'suspicious', code: 'ip_host', message: `Link points directly at the IP address ${host}.` });
  }
  if (host.includes('xn--')) {
    findings.push({ level: 'suspicious', code: 'punycode_host', message: `Link host "${host}" looks like a look-alike domain.` });
  }
  if (SHORTENER_DOMAINS.has(baseDomain(host)) || SHORTENER_DOMAINS.has(host)) {
    findings.push({ level: 'suspicious', code: 'shortened_url', message: `Link uses the shortener ${host}.` });
  }

  const pathExt = extensionOf(url.pathname);
  if (pathExt && DANGEROUS_EXTENSIONS.has(pathExt)) {
    findings.push({
      level: 'malicious',
      code: 'executable_download_link',
      message: `Link downloads a .${pathExt} file.`,
    });
  }
}

function hasForeignLink(email) {
  const address = String((email.from && email.from.address) || '');
  const at = address.lastIndexOf('@');
  const senderBase = at > 0 ? baseDomain(address.slice(at + 1)) : '';
  if (!senderBase) return true;
  for (const link of email.links || []) {
    try {
      const host = new URL(String(link)).hostname.toLowerCase().replace(/^\[|\]$/g, '');
      if (host && baseDomain(host) !== senderBase) return true;
    } catch {
      return true;
    }
  }
  return false;
}

function checkWording(email, findings) {
  const subject = String(email.subject || '');
  const body = `${String(email.text || '')}\n${String(email.preview || '')}`.slice(0, 20000);

  const subjectHit = PHISHING_PHRASES.some((re) => re.test(subject));
  const bodyHit = PHISHING_PHRASES.some((re) => re.test(body));
  if (!subjectHit && !bodyHit) return;

  const attachments = (email.attachments || []).length;
  const hasLinks = (email.links || []).length > 0;
  const hasPayload = hasLinks || attachments > 0;

  // Credential wording alone is common in genuine security notices; escalate only
  // when it appears in the subject, next to an attachment, or beside a link that
  // points away from the sender's own domain.
  const escalated = hasPayload && (subjectHit || attachments > 0 || (hasLinks && hasForeignLink(email)));

  if (escalated) {
    findings.push({
      level: 'suspicious',
      code: 'phishing_wording',
      message: 'Message uses credential/urgency wording together with a link or attachment.',
    });
  } else {
    findings.push({
      level: 'info',
      code: 'urgency_wording',
      message: 'Message uses credential/urgency wording but carries no link or attachment.',
    });
  }
}

// --- Optional malware scan result already present on the record -------------

const MALICIOUS_WORDS = /\b(malicious|malware|virus|infected|threat|trojan|ransomware|phishing|dangerous|high)\b/i;
const SUSPICIOUS_WORDS = /\b(suspicious|medium)\b/i;
const CLEAN_WORDS = /\b(clean|safe|benign|ok|low|no[_\s-]?threat|clear|passed)\b/i;
const ERRORED_WORDS = /\b(error|failed|failure|timeout|timed[_\s-]?out|unavailable|unknown|indeterminate|skipped)\b/i;

function verdictFromText(text) {
  const value = String(text || '').trim();
  if (!value) return null;
  if (MALICIOUS_WORDS.test(value)) return 'malicious';
  if (SUSPICIOUS_WORDS.test(value)) return 'suspicious';
  if (CLEAN_WORDS.test(value)) return 'clean';
  if (ERRORED_WORDS.test(value)) return 'errored';
  return null;
}

function verdictFromScan(scan) {
  if (scan == null) return null;
  if (typeof scan === 'string' || typeof scan === 'number' || typeof scan === 'boolean') {
    if (scan === true) return 'malicious';
    if (scan === false) return 'clean';
    return verdictFromText(scan);
  }
  if (typeof scan !== 'object') return null;

  if (scan.infected === true || scan.malicious === true || scan.isInfected === true || scan.threatFound === true) {
    return 'malicious';
  }
  if (scan.error || scan.errorMessage) return 'errored';

  const keys = ['result', 'verdict', 'status', 'scanStatus', 'risk', 'riskLevel', 'risk_level', 'classification', 'engine'];
  for (const key of keys) {
    const verdict = verdictFromText(scan[key]);
    if (verdict) return verdict;
  }
  return null;
}

function readScannerVerdict(email) {
  if (!email || typeof email !== 'object') return null;
  const candidates = [email.malwareScan, email.scanResult, email.scan, email.safety && email.safety.scan];
  for (const candidate of candidates) {
    const verdict = verdictFromScan(candidate);
    if (verdict) return verdict;
  }
  return null;
}

// --- Entry point -------------------------------------------------------------

/**
 * Analyse a parsed email and return `{ status, label, reasons }`.
 * Never throws: an analysis failure degrades to `unknown`, never to `safe`.
 */
export function assessEmailSafety(email) {
  try {
    if (!email || typeof email !== 'object') {
      return makeResult(UNKNOWN, ['No email data was available for analysis.']);
    }

    const findings = [];
    checkSender(email, findings);
    let unresolvedAttachments = 0;
    for (const att of email.attachments || []) {
      if (checkAttachment(att, findings)) unresolvedAttachments += 1;
    }
    for (const link of email.links || []) checkLink(link, findings);
    checkWording(email, findings);

    const verdict = readScannerVerdict(email);

    const reasons = findings.filter((f) => f.level !== 'info').map((f) => f.message);

    if (verdict === 'malicious' || verdict === 'suspicious') {
      reasons.unshift('Malware scan reported a threat.');
      return makeResult(DANGEROUS, reasons);
    }
    if (findings.some((f) => f.level === 'malicious' || f.level === 'suspicious')) {
      return makeResult(DANGEROUS, reasons);
    }
    if (verdict === 'errored') {
      reasons.push('The malware scanner could not determine the result.');
      return makeResult(UNKNOWN, reasons);
    }
    if (unresolvedAttachments > 0) {
      reasons.push('Attachment contents could not be verified, so the result is unknown.');
      return makeResult(UNKNOWN, reasons);
    }
    if (verdict === 'clean') {
      reasons.push('Malware scan reported no threat.');
      return makeResult(SAFE, reasons);
    }
    return makeResult(SAFE, reasons);
  } catch (err) {
    return makeResult(UNKNOWN, [`Safety analysis failed: ${err && err.message ? err.message : 'unknown error'}`]);
  }
}
