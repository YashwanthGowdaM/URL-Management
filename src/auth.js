import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const KDF = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64, KDF);
  return `s1$${salt.toString('hex')}$${key.toString('hex')}`;
}

export async function verifyPassword(password, stored) {
  const [ver, salt, hash] = stored.split('$');
  if (ver !== 's1') return false;
  const key = await scrypt(password, Buffer.from(salt, 'hex'), 64, KDF);
  return crypto.timingSafeEqual(key, Buffer.from(hash, 'hex'));
}

/* ---- TOTP (RFC 6238, SHA-1, 6 digits, 30s) ---- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function newSecret() {
  let bits = '', out = '';
  for (const byte of crypto.randomBytes(20)) bits += byte.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

export function b32decode(s) {
  let bits = '';
  for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function hotp(key, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, '0');
}

/** Returns the matched time-step, or null. Steps <= lastStep are rejected (replay protection). */
export function checkTotp(secret, code, lastStep = 0) {
  const key = b32decode(secret);
  const now = Math.floor(Date.now() / 30000);
  for (const drift of [-1, 0, 1]) {
    const step = now + drift;
    if (step <= lastStep) continue;
    if (safeEqual(hotp(key, step), code)) return step;
  }
  return null;
}

export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
