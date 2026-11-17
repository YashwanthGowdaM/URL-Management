import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

const dir = process.env.DATA_DIR || './data';
fs.mkdirSync(dir, { recursive: true });

export const db = new Database(path.join(dir, 'registry.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS links (
  id          INTEGER PRIMARY KEY,
  label       TEXT NOT NULL,
  url         TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS users (
  id             INTEGER PRIMARY KEY,
  username       TEXT NOT NULL UNIQUE,
  pass_hash      TEXT NOT NULL,
  totp_secret    TEXT,
  totp_last_step INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
`);
