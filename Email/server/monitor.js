import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ImapFlow } from 'imapflow';
import { getMailboxConfig } from './config.js';
import { parseRawEmail } from './parser.js';
import { assessEmailSafety } from './safety.js';

const SYNC_LIMIT = Math.max(1, parseInt(process.env.SYNC_LIMIT, 10) || 25);
const POLL_INTERVAL = Math.max(5, parseInt(process.env.POLL_INTERVAL, 10) || 30);
const BACKOFF_STEPS = [5000, 10000, 20000, 40000, 60000];

function safeMsg(err) {
  const raw = (err && (err.message || err.responseStatus || err.code)) || String(err || 'unknown error');
  return String(raw).replace(/\s+/g, ' ').trim().slice(0, 180);
}

function isAuthError(err) {
  if (!err) return false;
  if (err.authenticationFailed === true) return true;
  const code = `${err.code || ''} ${err.serverResponseCode || ''}`;
  if (/AUTHENTICATIONFAILED|INVALIDCREDENTIALS|AUTH/i.test(code)) return true;
  const msg = err.message || '';
  return /authentication (failed|error)|login (failed|denied)|invalid (credentials|password)|auth failed/i.test(msg);
}

/**
 * IMAP monitor: connects to the configured mailbox, detects incoming mail,
 * parses it and emits 'email' events. Emits 'status' on every state change.
 */
export class EmailMonitor extends EventEmitter {
  constructor(store) {
    super();
    this.store = store;
    this.state = 'stopped';
    this.code = 'stopped';
    this.message = 'Monitoring stopped.';
    this.startedAt = null;
    this.client = null;
    this._stop = false;
    this._runPromise = null;
    this._stopPromise = null;
    this._stopResolve = null;
    this._fetching = false;
    this._fetchQueued = false;
    this._pollTimer = null;
    this._attempts = 0;
  }

  getStatus() {
    const cfg = getMailboxConfig();
    return {
      state: this.state,
      code: this.code,
      message: this.message,
      configured: cfg.configured,
      mailbox: cfg.configured
        ? { address: cfg.monitored || cfg.user, host: cfg.host, source: cfg.source }
        : null,
      startedAt: this.startedAt,
    };
  }

  #setState(state, code, message) {
    const changed = this.state !== state || this.code !== code || this.message !== message;
    this.state = state;
    this.code = code;
    this.message = message;
    if (changed) this.emit('status', this.getStatus());
  }

  /** Start monitoring. Waits for the first connection result so callers get immediate feedback. */
  async start() {
    const cfg = getMailboxConfig();
    if (!cfg.configured) {
      this.#setState('error', 'not_configured', 'Email not configured. Open Settings and enter your IMAP account.');
      return this.getStatus();
    }
    if (this._runPromise) return this.#awaitFirstResult(10000);

    this._stop = false;
    this._attempts = 0;
    this._stopPromise = new Promise((resolve) => {
      this._stopResolve = resolve;
    });
    this.#setState('connecting', 'connecting', `Connecting to mailbox ${cfg.host}...`);
    this._runPromise = this.#run().finally(() => {
      this._runPromise = null;
      this.#clearPoll();
    });
    return this.#awaitFirstResult(25000);
  }

  /** Stop monitoring and close the IMAP connection. */
  async stop() {
    this._stop = true;
    this.#clearPoll();
    if (this._stopResolve) this._stopResolve();
    const client = this.client;
    this.client = null;
    if (client) {
      try {
        await client.logout();
      } catch {
        try {
          client.close();
        } catch {
          /* ignore */
        }
      }
    }
    this.#setState('stopped', 'stopped', 'Monitoring stopped.');
    if (this._runPromise) await this._runPromise.catch(() => {});
    this._stopPromise = null;
    this._stopResolve = null;
    return this.getStatus();
  }

  /** Re-read configuration and restart (used after Settings are saved). */
  async restart() {
    if (this.state !== 'stopped' || this._runPromise) await this.stop();
    return this.start();
  }

  /** Check the mailbox right now for messages newer than the newest stored one. */
  async refresh() {
    if (!this.client || !this.client.mailbox) {
      return { newCount: 0, message: this.message, connected: false };
    }
    const deadline = Date.now() + 15000;
    while (this._fetching && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    const before = this.store.count();
    await this.#syncNew(true);
    const newCount = this.store.count() - before;
    return {
      newCount,
      connected: true,
      message: newCount > 0 ? `Imported ${newCount} new email(s).` : 'No new emails.',
    };
  }

  #awaitFirstResult(timeoutMs) {
    const settled = ['active', 'error', 'stopped', 'reconnecting'];
    if (settled.includes(this.state)) return Promise.resolve(this.getStatus());
    return new Promise((resolve) => {
      const onStatus = (s) => {
        if (settled.includes(s.state)) {
          cleanup();
          resolve(s);
        }
      };
      const timer = setTimeout(() => {
        cleanup();
        resolve(this.getStatus());
      }, timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        this.off('status', onStatus);
      };
      this.on('status', onStatus);
    });
  }

  async #run() {
    while (!this._stop) {
      const cfg = getMailboxConfig();
      if (!cfg.configured) {
        this.#setState('error', 'not_configured', 'Email not configured. Open Settings and enter your IMAP account.');
        return;
      }

      let fatal = false;
      try {
        await this.#connectOnce(cfg);
        this._attempts = 0;
      } catch (err) {
        if (this._stop) return;
        if (isAuthError(err)) {
          fatal = true;
          this.#setState(
            'error',
            'auth_failed',
            'Authentication failed. Check the email address and password (use an App Password for Gmail/Google Workspace).',
          );
        } else if (err && err.code === 'NOT_CONFIGURED') {
          fatal = true;
          this.#setState('error', 'not_configured', 'Email not configured. Open Settings and enter your IMAP account.');
        } else {
          const delay = BACKOFF_STEPS[Math.min(this._attempts, BACKOFF_STEPS.length - 1)];
          this._attempts += 1;
          this.#setState(
            'reconnecting',
            'reconnecting',
            `Mailbox connection failed: ${safeMsg(err)}. Reconnecting in ${Math.ceil(delay / 1000)}s (attempt ${this._attempts})...`,
          );
          const slept = await this.#sleep(delay);
          if (slept === 'stopped' || this._stop) return;
        }
      }
      if (fatal) return;
    }
  }

  #connectOnce(cfg) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        this.#clearPoll();
        reject(err);
      };
      const done = () => {
        if (settled) return;
        settled = true;
        resolve();
      };

      const client = new ImapFlow({
        host: cfg.host,
        port: cfg.port,
        secure: cfg.secure,
        auth: { user: cfg.user, pass: cfg.pass },
        logger: false,
        socketTimeout: 60000,
        connectionTimeout: 30000,
        greetingTimeout: 30000,
        tls: { rejectUnauthorized: true },
      });
      this.client = client;

      client.on('error', (err) => fail(err || new Error('IMAP connection error')));
      client.on('close', () => fail(new Error('Mailbox connection closed by server')));
      if (this._stopPromise) this._stopPromise.then(() => fail(Object.assign(new Error('stopped'), { code: 'STOPPED' })));

      (async () => {
        await client.connect();
        if (this._stop) {
          try {
            await client.logout();
          } catch {
            /* ignore */
          }
          done();
          return;
        }
        await client.mailboxOpen('INBOX');

        client.on('exists', () => {
          this.#syncNew().catch(() => {
            /* connection-level errors surface via the error/close handlers */
          });
        });

        await this.#syncNew(true);

        this._attempts = 0;
        this.startedAt = new Date().toISOString();
        this.#setState('active', 'ok', 'Monitoring active. Listening for new emails in INBOX.');

        // Auto-IDLE is enabled by imapflow; the timer is a safety net that
        // catches anything an IDLE session might have missed.
        const pollMs = client.serverSupports && client.serverSupports('IDLE') ? 60000 : POLL_INTERVAL * 1000;
        this.#startPolling(pollMs);

        // Resolves only when the connection dies or monitoring is stopped.
      })().catch(fail);
    });
  }

  #startPolling(intervalMs) {
    this.#clearPoll();
    this._pollTimer = setInterval(() => {
      this.#syncNew().catch(() => {});
    }, intervalMs);
    if (typeof this._pollTimer.unref === 'function') this._pollTimer.unref();
  }

  #clearPoll() {
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
  }

  /** Fetch messages newer than the newest stored one (or backfill on first run). Serialized. */
  async #syncNew(force = false) {
    if (this._fetching) {
      if (force) this._fetchQueued = true;
      return;
    }
    this._fetching = true;
    try {
      const client = this.client;
      if (!client || !client.mailbox || this._stop) return;
      const lastUid = this.store.getLastUid();

      if (lastUid == null) {
        const exists = client.mailbox.exists || 0;
        if (!exists) return;
        const n = Math.min(SYNC_LIMIT, exists);
        const startSeq = Math.max(1, exists - n + 1);
        await this.#fetchRange(`${startSeq}:*`, false);
      } else {
        await this.#fetchRange(`${lastUid + 1}:*`, true);
      }
    } finally {
      this._fetching = false;
      if (this._fetchQueued) {
        this._fetchQueued = false;
        setImmediate(() => this.#syncNew(true).catch(() => {}));
      }
    }
  }

  async #fetchRange(range, useUid) {
    const client = this.client;
    const cfg = getMailboxConfig();
    for await (const msg of client.fetch(range, { uid: true, source: true }, { uid: useUid })) {
      if (this._stop) break;
      await this.#processMessage(msg, cfg);
    }
  }

  async #processMessage(msg, cfg) {
    if (!msg || !msg.source) return;
    if (msg.uid != null && this.store.has({ uid: msg.uid })) return;

    const email = await parseRawEmail(msg.source, {
      monitored: cfg.monitored || cfg.user,
      uid: msg.uid ?? null,
      folder: 'INBOX',
    });
    email.id = randomUUID();
    email.safety = assessEmailSafety(email);
    if (!this.store.add(email)) return;
    this.emit('email', email);

    // Sync directly to ThreatShield main project backend if active
    try {
      fetch('http://localhost:8000/api/email-security/sync-raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(email),
      }).catch(() => {});
    } catch {
      /* ThreatShield offline, ignore */
    }
  }

  #sleep(ms) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve('done'), ms);
      this._stopPromise?.then(() => {
        clearTimeout(timer);
        resolve('stopped');
      });
    });
  }
}
