import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from './crypto.js';
import { assessEmailSafety, safetyLabel } from './safety.js';

const FILE = path.join(DATA_DIR, 'emails.json');
const MAX_STORED = Math.max(10, parseInt(process.env.MAX_STORED_EMAILS, 10) || 500);

function atomicWrite(file, contents) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, contents);
  fs.renameSync(tmp, file);
}

/** Guarantee every stored record carries a safety status (never throws). */
function ensureSafety(email) {
  try {
    const result = assessEmailSafety(email);
    if (result && result.status) return result;
  } catch {
    /* fall through to the unknown placeholder below */
  }
  return { status: 'unknown', label: safetyLabel('unknown'), reasons: [] };
}

export class EmailStore {
  constructor() {
    this.emails = [];
    this.total = 0;
    this.lastUid = null;
    this.#load();
  }

  #load() {
    try {
      if (!fs.existsSync(FILE)) return;
      const raw = JSON.parse(fs.readFileSync(FILE, 'utf8'));
      if (Array.isArray(raw.emails)) this.emails = raw.emails;
      if (Number.isFinite(raw.total)) this.total = raw.total;
      if (Number.isFinite(raw.lastUid)) this.lastUid = raw.lastUid;
    } catch {
      // Corrupt/unreadable store: start fresh rather than crash the monitor.
      this.emails = [];
      this.total = 0;
      this.lastUid = null;
    }
    this.#backfillSafety();
  }

  /** Emails stored before the safety-status feature existed get analysed once on load. */
  #backfillSafety() {
    for (const email of this.emails) {
      if (!email || typeof email !== 'object' || email.safety?.status) continue;
      email.safety = ensureSafety(email);
    }
  }

  #save() {
    try {
      atomicWrite(FILE, JSON.stringify({ version: 1, total: this.total, lastUid: this.lastUid, emails: this.emails }));
    } catch (err) {
      // Never crash the monitor over a write failure; surface it to the caller.
      console.error(`[store] failed to persist emails: ${err.message}`);
    }
  }

  has({ uid, messageId }) {
    if (messageId && this.emails.some((e) => e.messageId === messageId)) return true;
    if (uid != null && this.emails.some((e) => e.uid === uid)) return true;
    return false;
  }

  add(email) {
    if (this.has(email)) return false;
    if (!email.safety?.status) email.safety = ensureSafety(email);
    this.emails.push(email);
    if (this.emails.length > MAX_STORED) this.emails.splice(0, this.emails.length - MAX_STORED);
    this.total += 1;
    if (email.uid != null && (this.lastUid == null || email.uid > this.lastUid)) this.lastUid = email.uid;
    this.#save();
    return true;
  }

  getLastUid() {
    return this.lastUid;
  }

  setLastUid(uid) {
    if (uid != null && (this.lastUid == null || uid > this.lastUid)) {
      this.lastUid = uid;
      this.#save();
    }
  }

  count() {
    return this.total;
  }

  storedCount() {
    return this.emails.length;
  }

  list(limit = 50, offset = 0) {
    const newestFirst = [...this.emails].reverse();
    return newestFirst.slice(offset, offset + limit);
  }

  get(id) {
    return this.emails.find((e) => e.id === id) || null;
  }

  lastEmailAt() {
    return this.emails.length ? this.emails[this.emails.length - 1].receivedAt : null;
  }
}
