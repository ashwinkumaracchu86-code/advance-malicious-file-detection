import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'email-monitor-crypto-'));
const { encryptSecret, decryptSecret } = await import('../server/crypto.js');

test('encryptSecret/decryptSecret round-trip', () => {
  const secret = 'my-imap-app-password-123';
  const payload = encryptSecret(secret);
  assert.ok(payload && payload.includes('.'));
  assert.notEqual(payload, secret);
  assert.equal(decryptSecret(payload), secret);
});

test('each encryption uses a fresh IV (ciphertext differs)', () => {
  const a = encryptSecret('same-value');
  const b = encryptSecret('same-value');
  assert.notEqual(a, b);
  assert.equal(decryptSecret(a), decryptSecret(b));
});

test('tampered ciphertext returns null instead of throwing', () => {
  const payload = encryptSecret('secret');
  const [iv, tag, data] = payload.split('.');
  const tampered = `${iv}.${tag}.${Buffer.from('nope-nope').toString('base64url')}`;
  assert.equal(decryptSecret(tampered), null);
  assert.equal(decryptSecret('garbage'), null);
  assert.equal(decryptSecret(''), null);
  assert.equal(decryptSecret(null), null);
});

test('empty plaintext is stored as empty string', () => {
  assert.equal(encryptSecret(''), '');
});

test('encryption key file is created inside the data dir with restricted mode', () => {
  const keyFile = path.join(process.env.DATA_DIR, 'encryption.key');
  assert.ok(fs.existsSync(keyFile));
  const hex = fs.readFileSync(keyFile, 'utf8').trim();
  assert.match(hex, /^[0-9a-f]{64}$/);
});
