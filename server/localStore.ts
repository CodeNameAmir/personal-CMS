import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { ApiTokenRecord, Category, CreatedApiToken, ImportResult, LogEntry, Tag } from '../src/types/logbook';
import { defaultTagColor, normalizeTagName } from '../src/utils/logFormatters';
import type { ParsedImportRecord } from '../src/utils/logFormatters';
import { hashPassword, verifyPassword } from './auth';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'logbook.db');

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    last_used_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    color TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, name),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    color TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, name),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    category_id TEXT,
    pinned INTEGER NOT NULL DEFAULT 0,
    attachment_name TEXT,
    attachment_path TEXT,
    attachment_size INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS log_tags (
    log_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    PRIMARY KEY (log_id, tag_id),
    FOREIGN KEY(log_id) REFERENCES logs(id) ON DELETE CASCADE,
    FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_logs_user_created ON logs(user_id, pinned DESC, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id);
  CREATE INDEX IF NOT EXISTS idx_tags_user ON tags(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
`);

function hashApiToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function seedDemoUserIfMissing(): void {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('demo') as
    | { id: string }
    | undefined;
  if (existing) return;

  const userId = crypto.randomUUID();
  const now = new Date();
  const iso = (daysAgo: number, minsAgo = 0) =>
    new Date(now.getTime() - daysAgo * 86400_000 - minsAgo * 60_000).toISOString();

  db.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
    userId,
    'demo',
    hashPassword('demo1234'),
    iso(10)
  );

  const catGeneral = crypto.randomUUID();
  const catApi = crypto.randomUUID();
  const catDeploy = crypto.randomUUID();
  const catNotes = crypto.randomUUID();

  const insertCat = db.prepare(
    'INSERT INTO categories (id, user_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)'
  );
  insertCat.run(catGeneral, userId, 'General', '#64748b', iso(10));
  insertCat.run(catApi, userId, 'API', '#3b82f6', iso(10));
  insertCat.run(catDeploy, userId, 'Deployment', '#10b981', iso(10));
  insertCat.run(catNotes, userId, 'Notes', '#f59e0b', iso(10));

  const tagMap = new Map<string, string>();
  const ensureTag = (name: string, color: string) => {
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO tags (id, user_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)').run(
      id,
      userId,
      name,
      color,
      iso(9)
    );
    tagMap.set(name, id);
    return id;
  };

  ensureTag('prod', '#f59e0b');
  ensureTag('nginx', '#10b981');
  ensureTag('auth', '#3b82f6');
  ensureTag('backup', '#06b6d4');
  ensureTag('github', '#8b5cf6');
  ensureTag('rtl', '#ec4899');

  const sampleEntries = [
    {
      message: 'RENDER "AUTH_SESSION_SECRET" rotated across production gateway nodes',
      categoryId: catApi,
      pinned: 1,
      tags: ['prod', 'auth'],
      created: iso(0, 45),
    },
    {
      message: 'این سایت رو برام طراحی کن قراره کدها رو در گیتهاب قرار بدم و با github pages بیلد بگیرم',
      categoryId: catNotes,
      pinned: 1,
      tags: ['github', 'rtl'],
      created: iso(1, 20),
    },
    {
      message: 'Nginx reverse proxy upstream keepalive tuned to 64 connections on edge-01',
      categoryId: catDeploy,
      pinned: 0,
      tags: ['prod', 'nginx'],
      created: iso(2, 10),
    },
    {
      message: 'بکاپ گیری روزانه از دیتابیس و انتقال امن به مخزن پشتیبان انجام شد',
      categoryId: catGeneral,
      pinned: 0,
      tags: ['backup', 'rtl'],
      created: iso(3, 15),
    },
    {
      message: 'Verified geoip private subnet allowlist: 192.168.0.0/16, 10.0.0.0/8, localhost',
      categoryId: catApi,
      pinned: 0,
      tags: ['prod', 'nginx'],
      created: iso(4, 30),
    },
    {
      message: 'Synced model weights mirror index and verified SHA-256 checksums',
      categoryId: catDeploy,
      pinned: 0,
      tags: ['backup'],
      created: iso(6, 50),
    },
  ];

  const insertLog = db.prepare(
    'INSERT INTO logs (id, user_id, message, category_id, pinned, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  const insertLogTag = db.prepare('INSERT INTO log_tags (log_id, tag_id) VALUES (?, ?)');

  for (const item of sampleEntries) {
    const logId = crypto.randomUUID();
    insertLog.run(logId, userId, item.message, item.categoryId, item.pinned, item.created, item.created);
    for (const tagName of item.tags) {
      const tid = tagMap.get(tagName);
      if (tid) insertLogTag.run(logId, tid);
    }
  }
}

seedDemoUserIfMissing();

export function localSignup(usernameRaw: string, password: string): { id: string; username: string } {
  const username = usernameRaw.trim().toLowerCase();
  if (!/^[a-z0-9_.-]{2,32}$/.test(username)) {
    throw new Error('Username must be 2–32 characters (letters, numbers, _, ., -)');
  }
  if (password.length < 6) {
    throw new Error('Password must be at least 6 characters');
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    throw new Error('Username is already taken');
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
    userId,
    username,
    hashPassword(password),
    now
  );

  const insertCat = db.prepare(
    'INSERT INTO categories (id, user_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)'
  );
  insertCat.run(crypto.randomUUID(), userId, 'General', '#64748b', now);
  insertCat.run(crypto.randomUUID(), userId, 'API', '#3b82f6', now);
  insertCat.run(crypto.randomUUID(), userId, 'Notes', '#f59e0b', now);

  return { id: userId, username };
}

export function localLogin(usernameRaw: string, password: string): { id: string; username: string } {
  const username = usernameRaw.trim().toLowerCase();
  const row = db
    .prepare('SELECT id, username, password_hash FROM users WHERE username = ?')
    .get(username) as { id: string; username: string; password_hash: string } | undefined;

  if (!row || !verifyPassword(password, row.password_hash)) {
    throw new Error('Invalid username or password');
  }
  return { id: row.id, username: row.username };
}

export function localChangePassword(userId: string, currentPassword: string, newPassword: string): void {
  if (newPassword.length < 6) {
    throw new Error('New password must be at least 6 characters');
  }
  const row = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId) as
    | { password_hash: string }
    | undefined;
  if (!row || !verifyPassword(currentPassword, row.password_hash)) {
    throw new Error('Current password is incorrect');
  }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), userId);
}

/* ---------------- API Tokens ---------------- */
export function localListApiTokens(userId: string): ApiTokenRecord[] {
  return db
    .prepare(
      'SELECT id, name, token_prefix, last_used_at, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(userId) as unknown as ApiTokenRecord[];
}

export function localCreateApiToken(userId: string, nameRaw: string): CreatedApiToken {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Token name is required');

  const rawToken = `lbk_${crypto.randomBytes(24).toString('hex')}`;
  const tokenPrefix = `${rawToken.slice(0, 12)}…`;
  const tokenHash = hashApiToken(rawToken);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  db.prepare(
    'INSERT INTO api_tokens (id, user_id, name, token_prefix, token_hash, last_used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, userId, name, tokenPrefix, tokenHash, null, now);

  return {
    id,
    name,
    token_prefix: tokenPrefix,
    last_used_at: null,
    created_at: now,
    raw_token: rawToken,
  };
}

export function localDeleteApiToken(userId: string, tokenId: string): void {
  const res = db.prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(tokenId, userId);
  if (res.changes === 0) throw new Error('API token not found');
}

export function localResolveApiToken(rawToken: string): { userId: string } | null {
  const tokenHash = hashApiToken(rawToken);
  const row = db
    .prepare('SELECT id, user_id FROM api_tokens WHERE token_hash = ?')
    .get(tokenHash) as { id: string; user_id: string } | undefined;
  if (!row) return null;
  db.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').run(
    new Date().toISOString(),
    row.id
  );
  return { userId: row.user_id };
}

/* ---------------- Categories & Tags ---------------- */
export function localListCategories(userId: string): Category[] {
  const rows = db
    .prepare(
      `SELECT c.id, c.name, c.color, c.created_at, COUNT(l.id) AS log_count
       FROM categories c
       LEFT JOIN logs l ON l.category_id = c.id AND l.user_id = c.user_id
       WHERE c.user_id = ?
       GROUP BY c.id
       ORDER BY c.name COLLATE NOCASE ASC`
    )
    .all(userId) as Array<{
    id: string;
    name: string;
    color: string;
    created_at: string;
    log_count: number;
  }>;
  return rows.map((r) => ({ ...r, log_count: Number(r.log_count) }));
}

export function localCreateCategory(userId: string, nameRaw: string, colorRaw: string): Category {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Category name is required');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : '#3b82f6';

  const existing = db
    .prepare('SELECT id FROM categories WHERE user_id = ? AND LOWER(name) = LOWER(?)')
    .get(userId, name);
  if (existing) throw new Error('Category already exists');

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO categories (id, user_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)').run(
    id,
    userId,
    name,
    color,
    now
  );
  return { id, name, color, created_at: now, log_count: 0 };
}

export function localFindOrCreateCategoryByName(userId: string, nameRaw: string): Category {
  const name = nameRaw.trim().slice(0, 64) || 'General';
  const existing = db
    .prepare('SELECT id, name, color, created_at FROM categories WHERE user_id = ? AND LOWER(name) = LOWER(?)')
    .get(userId, name) as Category | undefined;
  if (existing) return existing;
  return localCreateCategory(userId, name, '#3b82f6');
}

export function localUpdateCategory(
  userId: string,
  categoryId: string,
  nameRaw: string,
  colorRaw: string
): Category {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Category name is required');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : '#3b82f6';

  const existing = db
    .prepare('SELECT id, created_at FROM categories WHERE id = ? AND user_id = ?')
    .get(categoryId, userId) as { id: string; created_at: string } | undefined;
  if (!existing) throw new Error('Category not found');

  const dup = db
    .prepare('SELECT id FROM categories WHERE user_id = ? AND LOWER(name) = LOWER(?) AND id != ?')
    .get(userId, name, categoryId);
  if (dup) throw new Error('Another category with this name already exists');

  db.prepare('UPDATE categories SET name = ?, color = ? WHERE id = ? AND user_id = ?').run(
    name,
    color,
    categoryId,
    userId
  );
  return { id: categoryId, name, color, created_at: existing.created_at };
}

export function localDeleteCategory(userId: string, categoryId: string): void {
  const cat = db
    .prepare('SELECT id FROM categories WHERE id = ? AND user_id = ?')
    .get(categoryId, userId);
  if (!cat) throw new Error('Category not found');

  const general = db
    .prepare("SELECT id FROM categories WHERE user_id = ? AND LOWER(name) = 'general' AND id != ?")
    .get(userId, categoryId) as { id: string } | undefined;

  db.prepare('UPDATE logs SET category_id = ? WHERE user_id = ? AND category_id = ?').run(
    general ? general.id : null,
    userId,
    categoryId
  );
  db.prepare('DELETE FROM categories WHERE id = ? AND user_id = ?').run(categoryId, userId);
}

export function localListTags(userId: string): Tag[] {
  const rows = db
    .prepare(
      `SELECT t.id, t.name, t.color, t.created_at, COUNT(lt.log_id) AS usage_count
       FROM tags t
       LEFT JOIN log_tags lt ON lt.tag_id = t.id
       WHERE t.user_id = ?
       GROUP BY t.id
       ORDER BY usage_count DESC, t.name ASC`
    )
    .all(userId) as Array<{
    id: string;
    name: string;
    color: string;
    created_at: string;
    usage_count: number;
  }>;
  return rows.map((r) => ({ ...r, usage_count: Number(r.usage_count) }));
}

export function localCreateOrGetTag(userId: string, nameRaw: string, colorRaw?: string): Tag {
  const name = normalizeTagName(nameRaw);
  if (!name) throw new Error('Tag name is invalid');

  const existing = db
    .prepare('SELECT id, name, color, created_at FROM tags WHERE user_id = ? AND name = ?')
    .get(userId, name) as Tag | undefined;
  if (existing) return existing;

  const id = crypto.randomUUID();
  const color =
    colorRaw && /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : defaultTagColor(name);
  const now = new Date().toISOString();
  db.prepare('INSERT INTO tags (id, user_id, name, color, created_at) VALUES (?, ?, ?, ?, ?)').run(
    id,
    userId,
    name,
    color,
    now
  );
  return { id, name, color, created_at: now, usage_count: 0 };
}

export function localUpdateTag(userId: string, tagId: string, nameRaw: string, colorRaw: string): Tag {
  const name = normalizeTagName(nameRaw);
  if (!name) throw new Error('Tag name is invalid');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : defaultTagColor(name);

  const existing = db.prepare('SELECT id FROM tags WHERE id = ? AND user_id = ?').get(tagId, userId);
  if (!existing) throw new Error('Tag not found');

  const dup = db
    .prepare('SELECT id FROM tags WHERE user_id = ? AND name = ? AND id != ?')
    .get(userId, name, tagId);
  if (dup) throw new Error('A tag with this name already exists');

  db.prepare('UPDATE tags SET name = ?, color = ? WHERE id = ? AND user_id = ?').run(
    name,
    color,
    tagId,
    userId
  );
  return { id: tagId, name, color };
}

export function localDeleteTag(userId: string, tagId: string): void {
  const res = db.prepare('DELETE FROM tags WHERE id = ? AND user_id = ?').run(tagId, userId);
  if (res.changes === 0) throw new Error('Tag not found');
}

function hydrateTagsForLogs(userId: string, logIds: string[]): Map<string, Tag[]> {
  const map = new Map<string, Tag[]>();
  if (logIds.length === 0) return map;

  const placeholders = logIds.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT lt.log_id, t.id, t.name, t.color
       FROM log_tags lt
       JOIN tags t ON t.id = lt.tag_id
       WHERE t.user_id = ? AND lt.log_id IN (${placeholders})
       ORDER BY t.name ASC`
    )
    .all(userId, ...logIds) as Array<{ log_id: string; id: string; name: string; color: string }>;

  for (const r of rows) {
    const list = map.get(r.log_id) || [];
    list.push({ id: r.id, name: r.name, color: r.color });
    map.set(r.log_id, list);
  }
  return map;
}

export function localListLogs(userId: string): LogEntry[] {
  const rows = db
    .prepare(
      `SELECT l.id, l.message, l.category_id, COALESCE(c.name, 'Uncategorized') AS category_name,
              COALESCE(c.color, '#64748b') AS category_color, l.pinned,
              l.attachment_name, l.attachment_path, l.attachment_size, l.created_at, l.updated_at
       FROM logs l
       LEFT JOIN categories c ON c.id = l.category_id AND c.user_id = l.user_id
       WHERE l.user_id = ?
       ORDER BY l.pinned DESC, l.created_at DESC`
    )
    .all(userId) as Array<{
    id: string;
    message: string;
    category_id: string | null;
    category_name: string;
    category_color: string;
    pinned: number;
    attachment_name: string | null;
    attachment_path: string | null;
    attachment_size: number | null;
    created_at: string;
    updated_at: string;
  }>;

  const tagMap = hydrateTagsForLogs(
    userId,
    rows.map((r) => r.id)
  );

  return rows.map((r) => ({
    ...r,
    pinned: Boolean(r.pinned),
    tags: tagMap.get(r.id) || [],
  }));
}

export function localGetLog(userId: string, logId: string): LogEntry | null {
  const r = db
    .prepare(
      `SELECT l.id, l.message, l.category_id, COALESCE(c.name, 'Uncategorized') AS category_name,
              COALESCE(c.color, '#64748b') AS category_color, l.pinned,
              l.attachment_name, l.attachment_path, l.attachment_size, l.created_at, l.updated_at
       FROM logs l
       LEFT JOIN categories c ON c.id = l.category_id AND c.user_id = l.user_id
       WHERE l.id = ? AND l.user_id = ?`
    )
    .get(logId, userId) as
    | {
        id: string;
        message: string;
        category_id: string | null;
        category_name: string;
        category_color: string;
        pinned: number;
        attachment_name: string | null;
        attachment_path: string | null;
        attachment_size: number | null;
        created_at: string;
        updated_at: string;
      }
    | undefined;

  if (!r) return null;
  const tagMap = hydrateTagsForLogs(userId, [r.id]);
  return {
    ...r,
    pinned: Boolean(r.pinned),
    tags: tagMap.get(r.id) || [],
  };
}

function syncLogTags(userId: string, logId: string, tagNames: string[]): void {
  db.prepare('DELETE FROM log_tags WHERE log_id = ?').run(logId);
  const insertLink = db.prepare('INSERT OR IGNORE INTO log_tags (log_id, tag_id) VALUES (?, ?)');
  for (const raw of tagNames) {
    const clean = normalizeTagName(raw);
    if (!clean) continue;
    const tag = localCreateOrGetTag(userId, clean);
    insertLink.run(logId, tag.id);
  }
}

export function localCreateLog(
  userId: string,
  input: { message: string; category_id?: string | null; tags?: string[]; pinned?: boolean; created_at?: string }
): LogEntry {
  const message = input.message.trim();
  if (!message) throw new Error('Message is required');

  let categoryId: string | null = input.category_id || null;
  if (categoryId) {
    const validCat = db
      .prepare('SELECT id FROM categories WHERE id = ? AND user_id = ?')
      .get(categoryId, userId);
    if (!validCat) throw new Error('Selected category not found');
  }

  const id = crypto.randomUUID();
  const createdAt = input.created_at || new Date().toISOString();
  db.prepare(
    `INSERT INTO logs (id, user_id, message, category_id, pinned, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(id, userId, message, categoryId, input.pinned ? 1 : 0, createdAt, createdAt);

  if (Array.isArray(input.tags)) {
    syncLogTags(userId, id, input.tags);
  }

  return localGetLog(userId, id)!;
}

export function localUpdateLog(
  userId: string,
  logId: string,
  input: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean }
): LogEntry {
  const existing = localGetLog(userId, logId);
  if (!existing) throw new Error('Log not found');

  const message = input.message !== undefined ? input.message.trim() : existing.message;
  if (!message) throw new Error('Message is required');

  let categoryId = input.category_id !== undefined ? input.category_id : existing.category_id;
  if (categoryId) {
    const validCat = db
      .prepare('SELECT id FROM categories WHERE id = ? AND user_id = ?')
      .get(categoryId, userId);
    if (!validCat) throw new Error('Selected category not found');
  }

  const pinned = input.pinned !== undefined ? (input.pinned ? 1 : 0) : existing.pinned ? 1 : 0;
  const now = new Date().toISOString();

  db.prepare(
    'UPDATE logs SET message = ?, category_id = ?, pinned = ?, updated_at = ? WHERE id = ? AND user_id = ?'
  ).run(message, categoryId, pinned, now, logId, userId);

  if (input.tags !== undefined) {
    syncLogTags(userId, logId, input.tags);
  }

  return localGetLog(userId, logId)!;
}

export function localTogglePin(userId: string, logId: string): LogEntry {
  const existing = localGetLog(userId, logId);
  if (!existing) throw new Error('Log not found');
  const nextPinned = existing.pinned ? 0 : 1;
  db.prepare('UPDATE logs SET pinned = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(
    nextPinned,
    new Date().toISOString(),
    logId,
    userId
  );
  return localGetLog(userId, logId)!;
}

export function localDeleteLog(userId: string, logId: string): LogEntry | null {
  const existing = localGetLog(userId, logId);
  if (!existing) return null;
  db.prepare('DELETE FROM logs WHERE id = ? AND user_id = ?').run(logId, userId);
  return existing;
}

export function localSetAttachment(
  userId: string,
  logId: string,
  attachment: { name: string | null; path: string | null; size: number | null }
): LogEntry {
  const existing = localGetLog(userId, logId);
  if (!existing) throw new Error('Log not found');

  db.prepare(
    'UPDATE logs SET attachment_name = ?, attachment_path = ?, attachment_size = ?, updated_at = ? WHERE id = ? AND user_id = ?'
  ).run(attachment.name, attachment.path, attachment.size, new Date().toISOString(), logId, userId);

  return localGetLog(userId, logId)!;
}

export function localBulkAction(
  userId: string,
  logIds: string[],
  action: { type: 'pin' | 'unpin' | 'delete' | 'category' | 'add_tag'; category_id?: string | null; tag?: string }
): number {
  let affected = 0;
  for (const id of logIds) {
    const log = localGetLog(userId, id);
    if (!log) continue;
    if (action.type === 'pin') {
      localUpdateLog(userId, id, { pinned: true });
      affected += 1;
    } else if (action.type === 'unpin') {
      localUpdateLog(userId, id, { pinned: false });
      affected += 1;
    } else if (action.type === 'delete') {
      localDeleteLog(userId, id);
      affected += 1;
    } else if (action.type === 'category') {
      localUpdateLog(userId, id, { category_id: action.category_id ?? null });
      affected += 1;
    } else if (action.type === 'add_tag' && action.tag) {
      const merged = Array.from(new Set([...log.tags.map((t) => t.name), action.tag]));
      localUpdateLog(userId, id, { tags: merged });
      affected += 1;
    }
  }
  return affected;
}

export function localImportRecords(userId: string, records: ParsedImportRecord[]): ImportResult {
  const existingCats = localListCategories(userId);
  const catByName = new Map(existingCats.map((c) => [c.name.toLowerCase(), c]));
  const existingMsgs = new Set(localListLogs(userId).map((l) => l.message));

  let imported = 0;
  let skipped = 0;
  let failed = 0;
  const errors: string[] = [];

  for (let i = 0; i < records.length; i += 1) {
    const rec = records[i];
    try {
      if (existingMsgs.has(rec.message)) {
        skipped += 1;
        continue;
      }

      let cat = catByName.get(rec.category.toLowerCase());
      if (!cat) {
        cat = localCreateCategory(userId, rec.category, '#3b82f6');
        catByName.set(cat.name.toLowerCase(), cat);
      }

      localCreateLog(userId, {
        message: rec.message,
        category_id: cat.id,
        tags: rec.tags,
        pinned: rec.pinned,
        created_at: rec.created_at,
      });
      existingMsgs.add(rec.message);
      imported += 1;
    } catch (err) {
      failed += 1;
      errors.push(`Row ${i + 1}: ${err instanceof Error ? err.message : 'Failed to import'}`);
    }
  }

  return { imported, skipped, failed, errors };
}
