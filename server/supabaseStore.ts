import crypto from 'node:crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type { ApiTokenRecord, Category, CreatedApiToken, ImportResult, LogEntry, Tag } from '../src/types/logbook';
import { defaultTagColor, normalizeTagName, type ParsedImportRecord } from '../src/utils/logFormatters';
import { hashPassword, verifyPassword } from './auth';

export const SUPABASE_SETUP_SQL = `-- Run this SQL once in your Supabase Project → SQL Editor
create extension if not exists pgcrypto;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.api_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  token_prefix text not null,
  token_hash text unique not null,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  color text not null default '#3b82f6',
  created_at timestamptz not null default now(),
  unique (user_id, name)
);

create table if not exists public.tags (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  color text not null default '#64748b',
  created_at timestamptz not null default now(),
  unique (user_id, name)
);

create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  message text not null,
  category_id uuid references public.categories(id) on delete set null,
  pinned boolean not null default false,
  attachment_name text,
  attachment_path text,
  attachment_size bigint,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.log_tags (
  log_id uuid not null references public.logs(id) on delete cascade,
  tag_id uuid not null references public.tags(id) on delete cascade,
  primary key (log_id, tag_id)
);

create index if not exists idx_logs_user_created on public.logs(user_id, pinned desc, created_at desc);
create index if not exists idx_categories_user on public.categories(user_id);
create index if not exists idx_tags_user on public.tags(user_id);
create index if not exists idx_api_tokens_hash on public.api_tokens(token_hash);

-- Migrate foreign keys if tables were previously created against auth.users
alter table public.categories drop constraint if exists categories_user_id_fkey;
alter table public.categories add constraint categories_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.tags drop constraint if exists tags_user_id_fkey;
alter table public.tags add constraint tags_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.logs drop constraint if exists logs_user_id_fkey;
alter table public.logs add constraint logs_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;
alter table public.api_tokens drop constraint if exists api_tokens_user_id_fkey;
alter table public.api_tokens add constraint api_tokens_user_id_fkey
  foreign key (user_id) references public.users(id) on delete cascade not valid;

-- Ensure server-managed tables are accessible when using custom public.users auth
alter table public.users disable row level security;
alter table public.api_tokens disable row level security;
alter table public.categories disable row level security;
alter table public.tags disable row level security;
alter table public.logs disable row level security;
alter table public.log_tags disable row level security;
`;

function hashApiToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

export function isSupabaseConfigured(): boolean {
  const url = (process.env.SUPABASE_URL || '').trim();
  const key = (
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    ''
  ).trim();
  return Boolean(url && key);
}

function getSupabaseAdminClient(): SupabaseClient {
  const url = (process.env.SUPABASE_URL || '').trim();
  const key = (
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    ''
  ).trim();

  if (!url || !key) {
    throw new Error('Supabase secrets (SUPABASE_URL and SUPABASE_SECRET_KEY / SUPABASE_PUBLISHABLE_KEY) are not configured on the server.');
  }

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

function handleSupabaseError(err: { message?: string; code?: string } | null): never {
  if (!err) throw new Error('Supabase request failed');
  const msg = err.message || '';
  if (
    err.code === 'PGRST205' ||
    err.code === '42P01' ||
    msg.includes('does not exist') ||
    msg.includes('Could not find the table')
  ) {
    const schemaErr = new Error(
      'Supabase tables are not initialized in your database yet. Run the SQL schema in your Supabase SQL Editor.'
    );
    (schemaErr as Error & { code?: string }).code = 'SCHEMA_MISSING';
    throw schemaErr;
  }
  if (
    err.code === '23503' &&
    (msg.includes('_user_id_fkey') || msg.includes('violates foreign key constraint'))
  ) {
    const fkErr = new Error(
      'Your Supabase tables still reference old auth.users foreign keys. Run the updated SQL schema in your Supabase SQL Editor to migrate constraints to public.users.'
    );
    (fkErr as Error & { code?: string }).code = 'SCHEMA_MISSING';
    throw fkErr;
  }
  throw new Error(msg || 'Supabase error');
}

export async function supabaseSignup(
  usernameRaw: string,
  password: string
): Promise<{ id: string; username: string }> {
  const username = usernameRaw.trim().toLowerCase();
  if (!/^[a-z0-9_.-]{2,32}$/.test(username)) {
    throw new Error('Username must be 2–32 characters (letters, numbers, _, ., -)');
  }
  if (password.length < 6) {
    throw new Error('Password must be at least 6 characters');
  }

  const client = getSupabaseAdminClient();
  const { data: existing, error: checkErr } = await client
    .from('users')
    .select('id')
    .eq('username', username)
    .maybeSingle();

  if (checkErr) handleSupabaseError(checkErr);
  if (existing) throw new Error('Username is already taken');

  const { data: created, error: insertErr } = await client
    .from('users')
    .insert({
      username,
      password_hash: hashPassword(password),
    })
    .select('id, username')
    .single();

  if (insertErr || !created) handleSupabaseError(insertErr);

  // Seed starter categories for the new user
  const { error: seedErr } = await client.from('categories').insert([
    { user_id: created.id, name: 'General', color: '#64748b' },
    { user_id: created.id, name: 'API', color: '#3b82f6' },
    { user_id: created.id, name: 'Notes', color: '#f59e0b' },
  ]);
  if (seedErr) {
    await client.from('users').delete().eq('id', created.id);
    handleSupabaseError(seedErr);
  }

  return { id: String(created.id), username: String(created.username) };
}

export async function supabaseLogin(
  usernameRaw: string,
  password: string
): Promise<{ id: string; username: string }> {
  const username = usernameRaw.trim().toLowerCase();
  const client = getSupabaseAdminClient();

  const { data: user, error } = await client
    .from('users')
    .select('id, username, password_hash')
    .eq('username', username)
    .maybeSingle();

  if (error) handleSupabaseError(error);
  if (!user || !verifyPassword(password, String(user.password_hash))) {
    throw new Error('Invalid username or password');
  }

  return { id: String(user.id), username: String(user.username) };
}

export async function supabaseChangePassword(
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> {
  if (newPassword.length < 6) {
    throw new Error('New password must be at least 6 characters');
  }
  const client = getSupabaseAdminClient();
  const { data: user, error } = await client
    .from('users')
    .select('password_hash')
    .eq('id', userId)
    .maybeSingle();

  if (error) handleSupabaseError(error);
  if (!user || !verifyPassword(currentPassword, String(user.password_hash))) {
    throw new Error('Current password is incorrect');
  }

  const { error: updErr } = await client
    .from('users')
    .update({ password_hash: hashPassword(newPassword) })
    .eq('id', userId);

  if (updErr) handleSupabaseError(updErr);
}

/* ---------------- API Tokens ---------------- */
export async function supabaseListApiTokens(userId: string): Promise<ApiTokenRecord[]> {
  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('api_tokens')
    .select('id, name, token_prefix, last_used_at, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });

  if (error) handleSupabaseError(error);
  return (data || []) as ApiTokenRecord[];
}

export async function supabaseCreateApiToken(userId: string, nameRaw: string): Promise<CreatedApiToken> {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Token name is required');

  const rawToken = `lbk_${crypto.randomBytes(24).toString('hex')}`;
  const tokenPrefix = `${rawToken.slice(0, 12)}…`;
  const tokenHash = hashApiToken(rawToken);

  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('api_tokens')
    .insert({
      user_id: userId,
      name,
      token_prefix: tokenPrefix,
      token_hash: tokenHash,
    })
    .select('id, name, token_prefix, last_used_at, created_at')
    .single();

  if (error || !data) handleSupabaseError(error);
  return { ...(data as ApiTokenRecord), raw_token: rawToken };
}

export async function supabaseDeleteApiToken(userId: string, tokenId: string): Promise<void> {
  const client = getSupabaseAdminClient();
  const { error } = await client.from('api_tokens').delete().eq('id', tokenId).eq('user_id', userId);
  if (error) handleSupabaseError(error);
}

export async function supabaseResolveApiToken(rawToken: string): Promise<{ userId: string } | null> {
  if (!isSupabaseConfigured()) return null;
  try {
    const client = getSupabaseAdminClient();
    const tokenHash = hashApiToken(rawToken);
    const { data, error } = await client
      .from('api_tokens')
      .select('id, user_id')
      .eq('token_hash', tokenHash)
      .maybeSingle();

    if (error || !data) return null;
    await client
      .from('api_tokens')
      .update({ last_used_at: new Date().toISOString() })
      .eq('id', data.id);
    return { userId: String(data.user_id) };
  } catch {
    return null;
  }
}

/* ---------------- Categories & Tags ---------------- */
export async function supabaseListCategories(userId: string): Promise<Category[]> {
  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('categories')
    .select('id, name, color, created_at')
    .eq('user_id', userId)
    .order('name', { ascending: true });

  if (error) handleSupabaseError(error);
  return (data || []) as Category[];
}

export async function supabaseCreateCategory(
  userId: string,
  nameRaw: string,
  colorRaw: string
): Promise<Category> {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Category name is required');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : '#3b82f6';

  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('categories')
    .insert({ user_id: userId, name, color })
    .select('id, name, color, created_at')
    .single();

  if (error || !data) handleSupabaseError(error);
  return data as Category;
}

export async function supabaseFindOrCreateCategoryByName(
  userId: string,
  nameRaw: string
): Promise<Category> {
  const name = nameRaw.trim().slice(0, 64) || 'General';
  const existing = (await supabaseListCategories(userId)).find(
    (c) => c.name.toLowerCase() === name.toLowerCase()
  );
  if (existing) return existing;
  return supabaseCreateCategory(userId, name, '#3b82f6');
}

export async function supabaseUpdateCategory(
  userId: string,
  categoryId: string,
  nameRaw: string,
  colorRaw: string
): Promise<Category> {
  const name = nameRaw.trim().slice(0, 64);
  if (!name) throw new Error('Category name is required');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : '#3b82f6';

  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('categories')
    .update({ name, color })
    .eq('id', categoryId)
    .eq('user_id', userId)
    .select('id, name, color, created_at')
    .single();

  if (error || !data) handleSupabaseError(error);
  return data as Category;
}

export async function supabaseDeleteCategory(userId: string, categoryId: string): Promise<void> {
  const client = getSupabaseAdminClient();
  const { error } = await client.from('categories').delete().eq('id', categoryId).eq('user_id', userId);
  if (error) handleSupabaseError(error);
}

export async function supabaseListTags(userId: string): Promise<Tag[]> {
  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('tags')
    .select('id, name, color, created_at')
    .eq('user_id', userId)
    .order('name', { ascending: true });

  if (error) handleSupabaseError(error);
  return (data || []) as Tag[];
}

export async function supabaseCreateOrGetTag(
  userId: string,
  nameRaw: string,
  colorRaw?: string
): Promise<Tag> {
  const name = normalizeTagName(nameRaw);
  if (!name) throw new Error('Tag name is invalid');

  const client = getSupabaseAdminClient();
  const { data: existing, error: findErr } = await client
    .from('tags')
    .select('id, name, color, created_at')
    .eq('user_id', userId)
    .eq('name', name)
    .maybeSingle();

  if (findErr) handleSupabaseError(findErr);
  if (existing) return existing as Tag;

  const color =
    colorRaw && /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : defaultTagColor(name);
  const { data, error } = await client
    .from('tags')
    .insert({ user_id: userId, name, color })
    .select('id, name, color, created_at')
    .single();

  if (error || !data) handleSupabaseError(error);
  return data as Tag;
}

export async function supabaseUpdateTag(
  userId: string,
  tagId: string,
  nameRaw: string,
  colorRaw: string
): Promise<Tag> {
  const name = normalizeTagName(nameRaw);
  if (!name) throw new Error('Tag name is invalid');
  const color = /^#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$/.test(colorRaw) ? colorRaw : defaultTagColor(name);

  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('tags')
    .update({ name, color })
    .eq('id', tagId)
    .eq('user_id', userId)
    .select('id, name, color, created_at')
    .single();

  if (error || !data) handleSupabaseError(error);
  return data as Tag;
}

export async function supabaseDeleteTag(userId: string, tagId: string): Promise<void> {
  const client = getSupabaseAdminClient();
  const { error } = await client.from('tags').delete().eq('id', tagId).eq('user_id', userId);
  if (error) handleSupabaseError(error);
}

/* ---------------- Logs ---------------- */
export async function supabaseListLogs(userId: string): Promise<LogEntry[]> {
  const client = getSupabaseAdminClient();
  const { data, error } = await client
    .from('logs')
    .select(
      `id, message, category_id, pinned, attachment_name, attachment_path, attachment_size, created_at, updated_at,
       categories(name, color),
       log_tags(tags(id, name, color))`
    )
    .eq('user_id', userId)
    .order('pinned', { ascending: false })
    .order('created_at', { ascending: false });

  if (error) handleSupabaseError(error);

  return (data || []).map((row: Record<string, unknown>) => {
    const cat = row.categories as { name?: string; color?: string } | null;
    const rawLinks = (row.log_tags as Array<{ tags: Tag | null }> | null) || [];
    const tags = rawLinks.map((lt) => lt.tags).filter((t): t is Tag => Boolean(t));
    return {
      id: String(row.id),
      message: String(row.message),
      category_id: row.category_id ? String(row.category_id) : null,
      category_name: cat?.name || 'Uncategorized',
      category_color: cat?.color || '#64748b',
      tags,
      pinned: Boolean(row.pinned),
      attachment_name: row.attachment_name ? String(row.attachment_name) : null,
      attachment_path: row.attachment_path ? String(row.attachment_path) : null,
      attachment_size: typeof row.attachment_size === 'number' ? row.attachment_size : null,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
    };
  });
}

async function supabaseGetLog(userId: string, logId: string): Promise<LogEntry | null> {
  const all = await supabaseListLogs(userId);
  return all.find((l) => l.id === logId) || null;
}

async function supabaseSyncLogTags(userId: string, logId: string, tagNames: string[]): Promise<void> {
  const client = getSupabaseAdminClient();
  await client.from('log_tags').delete().eq('log_id', logId);
  for (const raw of tagNames) {
    const clean = normalizeTagName(raw);
    if (!clean) continue;
    const tag = await supabaseCreateOrGetTag(userId, clean);
    const { error } = await client.from('log_tags').insert({ log_id: logId, tag_id: tag.id });
    if (error && !error.message.includes('duplicate')) handleSupabaseError(error);
  }
}

export async function supabaseCreateLog(
  userId: string,
  input: { message: string; category_id?: string | null; tags?: string[]; pinned?: boolean; created_at?: string }
): Promise<LogEntry> {
  const message = input.message.trim();
  if (!message) throw new Error('Message is required');

  const client = getSupabaseAdminClient();
  const now = input.created_at || new Date().toISOString();
  const { data, error } = await client
    .from('logs')
    .insert({
      user_id: userId,
      message,
      category_id: input.category_id || null,
      pinned: Boolean(input.pinned),
      created_at: now,
      updated_at: now,
    })
    .select('id')
    .single();

  if (error || !data) handleSupabaseError(error);

  if (Array.isArray(input.tags) && input.tags.length > 0) {
    await supabaseSyncLogTags(userId, String(data.id), input.tags);
  }

  return (await supabaseGetLog(userId, String(data.id)))!;
}

export async function supabaseUpdateLog(
  userId: string,
  logId: string,
  input: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean }
): Promise<LogEntry> {
  const client = getSupabaseAdminClient();
  const patch: Record<string, unknown> = { updated_at: new Date().toISOString() };
  if (input.message !== undefined) {
    const msg = input.message.trim();
    if (!msg) throw new Error('Message is required');
    patch.message = msg;
  }
  if (input.category_id !== undefined) patch.category_id = input.category_id || null;
  if (input.pinned !== undefined) patch.pinned = Boolean(input.pinned);

  const { error } = await client.from('logs').update(patch).eq('id', logId).eq('user_id', userId);
  if (error) handleSupabaseError(error);

  if (input.tags !== undefined) {
    await supabaseSyncLogTags(userId, logId, input.tags);
  }

  const updated = await supabaseGetLog(userId, logId);
  if (!updated) throw new Error('Log not found');
  return updated;
}

export async function supabaseTogglePin(userId: string, logId: string): Promise<LogEntry> {
  const existing = await supabaseGetLog(userId, logId);
  if (!existing) throw new Error('Log not found');
  return supabaseUpdateLog(userId, logId, { pinned: !existing.pinned });
}

export async function supabaseDeleteLog(userId: string, logId: string): Promise<LogEntry | null> {
  const existing = await supabaseGetLog(userId, logId);
  if (!existing) return null;
  const client = getSupabaseAdminClient();
  const { error } = await client.from('logs').delete().eq('id', logId).eq('user_id', userId);
  if (error) handleSupabaseError(error);
  return existing;
}

export async function supabaseSetAttachment(
  userId: string,
  logId: string,
  attachment: { name: string | null; path: string | null; size: number | null }
): Promise<LogEntry> {
  const client = getSupabaseAdminClient();
  const { error } = await client
    .from('logs')
    .update({
      attachment_name: attachment.name,
      attachment_path: attachment.path,
      attachment_size: attachment.size,
      updated_at: new Date().toISOString(),
    })
    .eq('id', logId)
    .eq('user_id', userId);

  if (error) handleSupabaseError(error);
  const updated = await supabaseGetLog(userId, logId);
  if (!updated) throw new Error('Log not found');
  return updated;
}

export async function supabaseImportRecords(
  userId: string,
  records: ParsedImportRecord[]
): Promise<ImportResult> {
  const cats = await supabaseListCategories(userId);
  const catByName = new Map(cats.map((c) => [c.name.toLowerCase(), c]));
  const existingMsgs = new Set((await supabaseListLogs(userId)).map((l) => l.message));

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
        cat = await supabaseCreateCategory(userId, rec.category, '#3b82f6');
        catByName.set(cat.name.toLowerCase(), cat);
      }
      await supabaseCreateLog(userId, {
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
      errors.push(`Row ${i + 1}: ${err instanceof Error ? err.message : 'Failed'}`);
    }
  }

  return { imported, skipped, failed, errors };
}
