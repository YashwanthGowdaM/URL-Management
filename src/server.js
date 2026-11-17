import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { db } from './db.js';
import { hashPassword, verifyPassword, newSecret, checkTotp, safeEqual } from './auth.js';

const PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const ISSUER = 'URL Registry';
const COOKIE = PROD ? '__Host-sid' : 'sid';
const SESSION_TTL = 8 * 60 * 60 * 1000;
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

/* ---- first-run admin bootstrap ---- */
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const { ADMIN_USER, ADMIN_PASSWORD } = process.env;
  if (!ADMIN_USER || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
    console.error('First run: set ADMIN_USER and ADMIN_PASSWORD (min 12 chars).');
    process.exit(1);
  }
  db.prepare('INSERT INTO users (username, pass_hash) VALUES (?, ?)')
    .run(ADMIN_USER, await hashPassword(ADMIN_PASSWORD));
  console.log(`Admin user "${ADMIN_USER}" created. Remove ADMIN_PASSWORD from the environment.`);
}
const DUMMY_HASH = await hashPassword(crypto.randomBytes(8).toString('hex')); // equalises timing for unknown users

/* ---- app + headers ---- */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: PROD ? [] : null,
    },
  },
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));
app.use(express.json({ limit: '16kb' }));
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

app.get('/healthz', (_req, res) => { db.prepare('SELECT 1').get(); res.send('ok'); });

/* ---- sessions ---- */
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const rand = (n) => crypto.randomBytes(n).toString('base64url');
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function readCookie(req, name) {
  const hit = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(`${name}=`));
  return hit ? hit.slice(name.length + 1) : null;
}

function startSession(userId, res) {
  const token = rand(32), csrf = rand(24);
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
  db.prepare('INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES (?,?,?,?)')
    .run(sha(token), userId, csrf, Date.now() + SESSION_TTL);
  res.cookie(COOKIE, token, { httpOnly: true, secure: PROD, sameSite: 'strict', path: '/', maxAge: SESSION_TTL });
  return csrf;
}

app.use((req, _res, next) => {
  const token = readCookie(req, COOKIE);
  req.session = token
    ? db.prepare(`SELECT s.token_hash, s.csrf, u.id AS uid, u.username FROM sessions s
                  JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`)
        .get(sha(token), Date.now()) || null
    : null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session) return res.status(401).json({ error: 'Sign in to make changes.' });
  if (!safeEqual(req.get('x-csrf-token') || '', req.session.csrf))
    return res.status(403).json({ error: 'Request rejected. Reload the page and try again.' });
  next();
}

/* ---- auth: password -> TOTP ---- */
const pending = new Map();
setInterval(() => { for (const [k, v] of pending) if (v.exp < Date.now()) pending.delete(k); }, 60_000).unref();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
});

app.get('/api/auth/me', (req, res) => {
  res.json(req.session
    ? { authenticated: true, user: req.session.username, csrf: req.session.csrf }
    : { authenticated: false });
});

app.post('/api/auth/login', authLimiter, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || username.length > 64 || password.length > 256)
    return res.status(400).json({ error: 'Enter your username and password.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = await verifyPassword(password, user ? user.pass_hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Username or password is incorrect.' });

  const enroll = !user.totp_secret;
  const secret = user.totp_secret || newSecret();
  const id = rand(24);
  pending.set(id, { userId: user.id, secret, enroll, tries: 0, exp: Date.now() + 5 * 60_000 });

  const out = { pending: id, enroll };
  if (enroll) {
    const uri = `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(user.username)}`
      + `?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}`;
    out.qr = await QRCode.toDataURL(uri, { margin: 1, width: 200 });
    out.secret = secret;
  }
  res.json(out);
}));

app.post('/api/auth/verify', authLimiter, (req, res) => {
  const { pending: pid, code } = req.body || {};
  const p = typeof pid === 'string' ? pending.get(pid) : null;
  if (!p || p.exp < Date.now()) return res.status(401).json({ error: 'Sign-in timed out. Start again.' });
  if (++p.tries > 5) { pending.delete(pid); return res.status(429).json({ error: 'Too many wrong codes. Start again.' }); }
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code.' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(p.userId);
  const step = checkTotp(p.secret, code, p.enroll ? 0 : user.totp_last_step);
  if (step === null) return res.status(401).json({ error: 'That code is not valid.' });

  db.prepare('UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?').run(p.secret, step, user.id);
  pending.delete(pid);
  res.json({ user: user.username, csrf: startSession(user.id, res) });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.session.token_hash);
  res.clearCookie(COOKIE, { httpOnly: true, secure: PROD, sameSite: 'strict', path: '/' });
  res.json({ ok: true });
});

/* ---- links ---- */
function parseLink(body) {
  const label = typeof body?.label === 'string' ? body.label.trim() : '';
  const raw = typeof body?.url === 'string' ? body.url.trim() : '';
  const description = typeof body?.description === 'string' ? body.description.trim() : '';
  if (!label || label.length > 80) return { error: 'Label is required (80 characters max).' };
  if (!description || description.length > 300) return { error: 'Description is required (300 characters max).' };
  let u;
  try { u = new URL(raw); } catch { return { error: 'Enter a full URL, including https://' }; }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || raw.length > 2048)
    return { error: 'Only http and https URLs without embedded credentials are allowed.' };
  return { value: { label, url: u.href, description } };
}
const parseId = (v) => (/^\d{1,9}$/.test(v) ? Number(v) : null);

app.get('/api/links', (_req, res) => {
  res.json(db.prepare('SELECT id, label, url, description, updated_at FROM links ORDER BY label COLLATE NOCASE').all());
});

app.post('/api/links', requireAuth, (req, res) => {
  const { value, error } = parseLink(req.body);
  if (error) return res.status(400).json({ error });
  const r = db.prepare('INSERT INTO links (label, url, description) VALUES (@label, @url, @description)').run(value);
  res.status(201).json({ id: r.lastInsertRowid, ...value });
});

app.put('/api/links/:id', requireAuth, (req, res) => {
  const id = parseId(req.params.id);
  const { value, error } = parseLink(req.body);
  if (id === null || error) return res.status(400).json({ error: error || 'Invalid id.' });
  const r = db.prepare(`UPDATE links SET label=@label, url=@url, description=@description,
                        updated_at=datetime('now') WHERE id=@id`).run({ ...value, id });
  if (!r.changes) return res.status(404).json({ error: 'Link not found.' });
  res.json({ id, ...value });
});

app.delete('/api/links/:id', requireAuth, (req, res) => {
  const id = parseId(req.params.id);
  if (id === null) return res.status(400).json({ error: 'Invalid id.' });
  const r = db.prepare('DELETE FROM links WHERE id = ?').run(id);
  if (!r.changes) return res.status(404).json({ error: 'Link not found.' });
  res.json({ ok: true });
});

app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }));
app.use(express.static(publicDir, { maxAge: '1h' }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed request.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

const server = app.listen(PORT, () => console.log(`URL Registry listening on :${PORT}`));
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => server.close(() => { db.close(); process.exit(0); }));
