import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { DATA_DIR, encryptSecret, decryptSecret } from './crypto.js';

const ENV_FILE = path.join(DATA_DIR, '..', '.env');
dotenv.config({ path: ENV_FILE });

const SETTINGS_FILE = path.join(DATA_DIR, 'config.json');

function readSettingsFile() {
  try {
    if (!fs.existsSync(SETTINGS_FILE)) return null;
    const parsed = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

function writeSettingsFile(obj) {
  const tmp = `${SETTINGS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, SETTINGS_FILE);
}

function envConfig() {
  const host = (process.env.IMAP_HOST || '').trim();
  const user = (process.env.IMAP_USER || '').trim();
  if (!host || !user) return null;
  return {
    host,
    port: parseInt(process.env.IMAP_PORT, 10) || 993,
    secure: String(process.env.IMAP_SECURE ?? 'true').toLowerCase() !== 'false',
    user,
    pass: process.env.IMAP_PASS || '',
    monitored: (process.env.MONITORED_EMAIL || '').trim() || user,
  };
}

function savedConfig() {
  const s = readSettingsFile();
  if (!s || !s.host || !s.user) return null;
  return {
    host: String(s.host),
    port: Number(s.port) || 993,
    secure: s.secure !== false,
    user: String(s.user),
    pass: decryptSecret(s.passEnc) || '',
    monitored: (s.monitored || '').trim() || String(s.user),
  };
}

/** Effective mailbox configuration. `pass` is internal only - never send it to clients. */
export function getMailboxConfig() {
  const saved = savedConfig();
  const fromEnv = envConfig();
  const cfg = saved || fromEnv;
  if (!cfg) {
    return { configured: false, source: null, host: '', port: 993, secure: true, user: '', pass: '', monitored: '' };
  }
  return { configured: Boolean(cfg.host && cfg.user && cfg.pass), source: saved ? 'settings' : 'env', ...cfg };
}

/** Safe, redacted view for API responses. */
export function getPublicSettings() {
  const cfg = getMailboxConfig();
  return {
    configured: cfg.configured,
    source: cfg.source,
    host: cfg.host,
    port: cfg.port,
    secure: cfg.secure,
    user: cfg.user,
    monitored: cfg.monitored,
    hasPassword: Boolean(cfg.pass),
  };
}

const HOST_RE = /^[A-Za-z0-9.-]+$/;

/** Validate and persist settings from the dashboard (password encrypted at rest). */
export function saveSettings(input = {}) {
  const errors = [];
  const current = readSettingsFile() || {};
  const eff = getMailboxConfig();

  const host = String(input.host ?? current.host ?? eff.host ?? '').trim();
  const user = String(input.user ?? current.user ?? eff.user ?? '').trim();
  const portRaw = input.port ?? current.port ?? eff.port ?? 993;
  const port = Number(portRaw);
  const secure = input.secure === undefined ? (current.secure ?? eff.secure ?? true) : Boolean(input.secure);
  const monitored = String(input.monitored ?? current.monitored ?? eff.monitored ?? '').trim();

  if (!host) errors.push('IMAP host is required.');
  else if (!HOST_RE.test(host)) errors.push('IMAP host contains invalid characters.');
  if (!user) errors.push('Email address is required.');
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user)) errors.push('Email address looks invalid.');
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('Port must be between 1 and 65535.');
  if (typeof input.pass === 'string' && input.pass.length > 512) errors.push('Password is too long.');
  if (errors.length) {
    const err = new Error(errors.join(' '));
    err.status = 400;
    err.code = 'invalid_settings';
    throw err;
  }

  let passEnc = current.passEnc ?? null;
  if (typeof input.pass === 'string' && input.pass.length > 0) {
    passEnc = encryptSecret(input.pass);
  } else if (!passEnc && eff.pass) {
    // Carry over the currently working password (e.g. from .env) so saving never breaks monitoring.
    passEnc = encryptSecret(eff.pass);
  }

  writeSettingsFile({
    host,
    port,
    secure,
    user,
    monitored: monitored || user,
    passEnc,
    updatedAt: new Date().toISOString(),
  });

  return getPublicSettings();
}
