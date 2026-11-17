import test from 'node:test';
import assert from 'node:assert/strict';
import { hotp, b32decode, newSecret, hashPassword, verifyPassword } from '../src/auth.js';

test('HOTP matches RFC 6238 vector (T=59s)', () => {
  const key = b32decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(hotp(key, 1), '287082');
});

test('generated secret is 32 base32 chars', () => {
  assert.match(newSecret(), /^[A-Z2-7]{32}$/);
});

test('password hash round trip', async () => {
  const h = await hashPassword('correct horse battery');
  assert.ok(await verifyPassword('correct horse battery', h));
  assert.ok(!(await verifyPassword('wrong', h)));
});
