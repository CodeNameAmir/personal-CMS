import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type {
  ApiTokenRecord,
  AppConfig,
  Category,
  CreatedApiToken,
  ImportResult,
  LogEntry,
  LogFilters,
  LogStats,
  Tag,
  UserSession,
  WorkspaceQuery,
} from '../types/logbook';
import {
  MAX_IMPORT_BYTES,
  MAX_IMPORT_RECORDS,
  parseImportCSV,
  parseImportJSON,
  serializeLogsToCSV,
  serializeLogsToJSON,
} from '../utils/logFormatters';
import { SUPABASE_SETUP_SQL } from './supabaseSchema';

// Clean up any legacy localStorage session artifacts from earlier builds
try {
  localStorage.removeItem('logbook_session_token');
  localStorage.removeItem('logbook_session_user');
} catch {
  // ignore storage errors
}

// Used ONLY when running on static hosting without the Express BFF (never persisted to localStorage)
let inMemoryStaticToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

let cachedConfig: AppConfig | null = null;
let cachedClient: SupabaseClient | null = null;

const authBroadcast =
  typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('logbook_auth_events') : null;

export function subscribeAuthEvents(onSignedOut: () => void): () => void {
  if (!authBroadcast) return () => {};
  const listener = (ev: MessageEvent) => {
    if (ev.data === 'logout') {
      inMemoryStaticToken = null;
      onSignedOut();
    }
  };
  authBroadcast.addEventListener('message', listener);
  return () => authBroadcast.removeEventListener('message', listener);
}

export function setUnauthorizedHandler(handler: () => void): void {
  unauthorizedHandler = handler;
}

export class ApiError extends Error {
  code?: string;
  status: number;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function getBuildTimeConfig(): AppConfig {
  const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env || {};
  const supabaseUrl = (env.VITE_SUPABASE_URL || '').trim();
  const supabasePublishableKey = (
    env.VITE_SUPABASE_PUBLISHABLE_KEY ||
    env.VITE_SUPABASE_ANON_KEY ||
    ''
  ).trim();
  return {
    bffEnabled: false,
    supabaseUrl,
    supabasePublishableKey,
    supabaseConfigured: Boolean(supabaseUrl && supabasePublishableKey),
  };
}

export async function fetchConfig(): Promise<AppConfig> {
  if (cachedConfig) return cachedConfig;

  try {
    const res = await fetch('/api/config', { credentials: 'include' });
    const contentType = res.headers.get('content-type') || '';
    if (res.ok && contentType.includes('application/json')) {
      const data = (await res.json()) as Partial<AppConfig>;
      const buildCfg = getBuildTimeConfig();
      const url = (data.supabaseUrl || buildCfg.supabaseUrl || '').trim();
      const key = (data.supabasePublishableKey || buildCfg.supabasePublishableKey || '').trim();
      cachedConfig = {
        bffEnabled: data.bffEnabled !== false,
        supabaseUrl: url,
        supabasePublishableKey: key,
        supabaseConfigured: Boolean(url && key),
      };
      return cachedConfig;
    }
  } catch {
    // Static hosts (GitHub Pages) will not have /api/config
  }

  cachedConfig = getBuildTimeConfig();
  return cachedConfig;
}

export function getLoadedConfig(): AppConfig {
  return cachedConfig || getBuildTimeConfig();
}

export async function fetchSupabaseSchema(): Promise<{ sql: string }> {
  return { sql: SUPABASE_SETUP_SQL };
}

async function getStaticSupabaseClient(): Promise<{ client: SupabaseClient; config: AppConfig }> {
  const cfg = await fetchConfig();
  if (!cfg.supabaseConfigured) {
    throw new ApiError(
      'Supabase environment variables (VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY) are not configured yet.',
      503,
      'SUPABASE_NOT_CONFIGURED'
    );
  }
  if (!cachedClient) {
    cachedClient = createClient(cfg.supabaseUrl, cfg.supabasePublishableKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }
  return { client: cachedClient, config: cfg };
}

function mapRpcError(
  err: { message?: string; code?: string } | null,
  options: { triggerUnauthorized?: boolean } = {}
): never {
  const msg = err?.message || 'Supabase request failed';
  const code = err?.code || '';

  if (msg.includes('RATE_LIMITED:')) {
    const clean = msg.replace(/^.*RATE_LIMITED:\s*/i, '').trim() || 'Too many requests. Please try again later.';
    throw new ApiError(clean, 429, 'RATE_LIMITED');
  }

  if (msg.includes('UNAUTHORIZED:')) {
    const clean = msg.replace(/^.*UNAUTHORIZED:\s*/i, '').trim() || 'Session expired or invalid.';
    inMemoryStaticToken = null;
    if (options.triggerUnauthorized && unauthorizedHandler) {
      unauthorizedHandler();
    }
    throw new ApiError(clean, 401, 'UNAUTHORIZED');
  }

  if (
    code === 'PGRST202' ||
    code === 'PGRST205' ||
    code === '42P01' ||
    code === '42883' ||
    msg.includes('Could not find the function') ||
    msg.includes('Could not find the table') ||
    msg.includes('does not exist') ||
    (code === '23503' && (msg.includes('_user_id_fkey') || msg.includes('violates foreign key constraint')))
  ) {
    throw new ApiError(
      'Supabase database schema is not initialized yet. Run supabase/schema.sql in your Supabase SQL Editor.',
      400,
      'SCHEMA_MISSING'
    );
  }

  throw new ApiError(msg, 400, code || undefined);
}

async function callStaticRpc<T>(
  fn: string,
  params: Record<string, unknown>,
  options: { triggerUnauthorized?: boolean } = { triggerUnauthorized: true }
): Promise<T> {
  const { client } = await getStaticSupabaseClient();
  const { data, error } = await client.rpc(fn, params);
  if (error) {
    mapRpcError(error, options);
  }
  return data as T;
}

async function callBff<T>(
  path: string,
  init: RequestInit = {},
  options: { triggerUnauthorized?: boolean } = { triggerUnauthorized: true }
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.method && init.method.toUpperCase() !== 'GET' && init.method.toUpperCase() !== 'HEAD') {
    headers.set('X-Requested-With', 'XMLHttpRequest');
  }
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(path, {
    ...init,
    credentials: 'include',
    headers,
  });

  const data = (await res.json().catch(() => null)) as { error?: string; code?: string } | null;

  if (!res.ok) {
    const code = data?.code;
    const message = data?.error || res.statusText || 'Request failed';
    if (res.status === 401) {
      if (options.triggerUnauthorized && unauthorizedHandler) {
        unauthorizedHandler();
      }
      throw new ApiError(message, 401, code || 'UNAUTHORIZED');
    }
    throw new ApiError(message, res.status, code);
  }

  return data as T;
}

function requireStaticToken(): string {
  if (!inMemoryStaticToken) {
    if (unauthorizedHandler) unauthorizedHandler();
    throw new ApiError('Missing session token', 401, 'UNAUTHORIZED');
  }
  return inMemoryStaticToken;
}

/* ---------------- Auth ---------------- */
export async function login(payload: {
  username: string;
  password: string;
}): Promise<{ user: UserSession }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ user: UserSession }>(
      '/api/auth/login',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { triggerUnauthorized: false }
    );
  }

  const res = await callStaticRpc<{ token: string; user: UserSession }>(
    'lb_login',
    { p_username: payload.username, p_password: payload.password },
    { triggerUnauthorized: false }
  );
  inMemoryStaticToken = res.token;
  return { user: res.user };
}

export async function signup(payload: {
  username: string;
  password: string;
}): Promise<{ user: UserSession }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ user: UserSession }>(
      '/api/auth/signup',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
      { triggerUnauthorized: false }
    );
  }

  const res = await callStaticRpc<{ token: string; user: UserSession }>(
    'lb_signup',
    { p_username: payload.username, p_password: payload.password },
    { triggerUnauthorized: false }
  );
  inMemoryStaticToken = res.token;
  return { user: res.user };
}

export async function restoreSession(): Promise<UserSession | null> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    if (!cfg.supabaseConfigured) return null;
    try {
      const res = await callBff<{ user: UserSession }>('/api/auth/me', {}, { triggerUnauthorized: false });
      return res.user;
    } catch {
      return null;
    }
  }

  if (!inMemoryStaticToken) return null;
  try {
    return await callStaticRpc<UserSession>(
      'lb_me',
      { p_token: inMemoryStaticToken },
      { triggerUnauthorized: false }
    );
  } catch {
    inMemoryStaticToken = null;
    return null;
  }
}

export async function logout(): Promise<void> {
  const cfg = await fetchConfig();
  authBroadcast?.postMessage('logout');

  if (cfg.bffEnabled) {
    try {
      await callBff<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }, { triggerUnauthorized: false });
    } catch {
      // ignore errors during sign out
    }
    return;
  }

  const token = inMemoryStaticToken;
  inMemoryStaticToken = null;
  if (!token) return;
  try {
    await callStaticRpc<boolean>('lb_logout', { p_token: token }, { triggerUnauthorized: false });
  } catch {
    // ignore errors during sign out
  }
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ ok: boolean }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }

  const res = await callStaticRpc<{ ok: boolean; token?: string }>('lb_change_password', {
    p_token: requireStaticToken(),
    p_current_password: currentPassword,
    p_new_password: newPassword,
  });
  if (res?.token) {
    inMemoryStaticToken = res.token;
  }
  return { ok: true };
}

/* ---------------- Workspace Snapshot (Server-Paginated) ---------------- */
export interface WorkspaceSnapshot {
  categories: Category[];
  tags: Tag[];
  logs: LogEntry[];
  total_count: number;
  page: number;
  page_size: number;
  stats: LogStats;
}

export async function fetchWorkspace(query: WorkspaceQuery): Promise<WorkspaceSnapshot> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    const params = new URLSearchParams({
      page: String(query.page),
      pageSize: String(query.pageSize),
      q: query.q,
      categoryId: query.categoryId,
      tags: query.selectedTags.join(','),
      tagMatchMode: query.tagMatchMode,
      dateFrom: query.dateFrom,
      pinnedOnly: String(query.pinnedOnly),
    });
    return callBff<WorkspaceSnapshot>(`/api/workspace?${params.toString()}`);
  }

  return callStaticRpc<WorkspaceSnapshot>('lb_get_workspace', {
    p_token: requireStaticToken(),
    p_page: query.page,
    p_page_size: query.pageSize,
    p_q: query.q,
    p_category_id: query.categoryId || null,
    p_tags: query.selectedTags,
    p_tag_match_mode: query.tagMatchMode,
    p_date_from: query.dateFrom || null,
    p_pinned_only: query.pinnedOnly,
  });
}

/* ---------------- API Tokens & Webhook ---------------- */
export async function listApiTokens(): Promise<ApiTokenRecord[]> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    const res = await callBff<{ tokens: ApiTokenRecord[] }>('/api/tokens');
    return res.tokens || [];
  }
  return callStaticRpc<ApiTokenRecord[]>('lb_list_api_tokens', {
    p_token: requireStaticToken(),
  });
}

export async function createApiToken(name: string): Promise<CreatedApiToken> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<CreatedApiToken>('/api/tokens', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
  }
  return callStaticRpc<CreatedApiToken>('lb_create_api_token', {
    p_token: requireStaticToken(),
    p_name: name,
  });
}

export async function deleteApiToken(id: string): Promise<{ ok: boolean }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ ok: boolean }>(`/api/tokens/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }
  await callStaticRpc<boolean>('lb_delete_api_token', {
    p_token: requireStaticToken(),
    p_id: id,
  });
  return { ok: true };
}

export async function sendWebhookLog(
  rawToken: string,
  payload: { message: string; category?: string; tags?: string[]; pinned?: boolean }
): Promise<{ log: LogEntry }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ log: LogEntry }>(
      '/api/webhook',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${rawToken}`,
        },
        body: JSON.stringify({
          message: payload.message,
          category: payload.category || 'Webhook',
          tags: payload.tags || [],
          pinned: Boolean(payload.pinned),
        }),
      },
      { triggerUnauthorized: false }
    );
  }

  if (!cfg.supabaseConfigured) {
    throw new ApiError('Supabase is not configured.', 503);
  }

  const res = await fetch(`${cfg.supabaseUrl.replace(/\/+$/, '')}/rest/v1/rpc/lb_ingest_webhook`, {
    method: 'POST',
    headers: {
      apikey: cfg.supabasePublishableKey,
      Authorization: `Bearer ${cfg.supabasePublishableKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      p_raw_token: rawToken,
      p_message: payload.message,
      p_category: payload.category || 'Webhook',
      p_tags: payload.tags || [],
      p_pinned: Boolean(payload.pinned),
    }),
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const errMsg = (data && (data.message || data.error)) || res.statusText || 'Webhook failed';
    throw new ApiError(errMsg.replace(/^.*UNAUTHORIZED:\s*/i, ''), res.status);
  }
  return data as { log: LogEntry };
}

/* ---------------- Categories ---------------- */
export async function createCategory(name: string, color: string): Promise<Category> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<Category>('/api/categories', {
      method: 'POST',
      body: JSON.stringify({ name, color }),
    });
  }
  return callStaticRpc<Category>('lb_create_category', {
    p_token: requireStaticToken(),
    p_name: name,
    p_color: color,
  });
}

export async function updateCategory(id: string, name: string, color: string): Promise<Category> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<Category>(`/api/categories/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ name, color }),
    });
  }
  return callStaticRpc<Category>('lb_update_category', {
    p_token: requireStaticToken(),
    p_id: id,
    p_name: name,
    p_color: color,
  });
}

export async function deleteCategory(id: string): Promise<{ ok: boolean }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ ok: boolean }>(`/api/categories/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }
  await callStaticRpc<boolean>('lb_delete_category', {
    p_token: requireStaticToken(),
    p_id: id,
  });
  return { ok: true };
}

/* ---------------- Tags ---------------- */
export async function createTag(name: string, color?: string): Promise<Tag> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<Tag>('/api/tags', {
      method: 'POST',
      body: JSON.stringify({ name, color: color || null }),
    });
  }
  return callStaticRpc<Tag>('lb_create_or_get_tag', {
    p_token: requireStaticToken(),
    p_name: name,
    p_color: color || null,
  });
}

export async function updateTag(id: string, name: string, color: string): Promise<Tag> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<Tag>(`/api/tags/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ name, color }),
    });
  }
  return callStaticRpc<Tag>('lb_update_tag', {
    p_token: requireStaticToken(),
    p_id: id,
    p_name: name,
    p_color: color,
  });
}

export async function deleteTag(id: string): Promise<{ ok: boolean }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ ok: boolean }>(`/api/tags/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }
  await callStaticRpc<boolean>('lb_delete_tag', {
    p_token: requireStaticToken(),
    p_id: id,
  });
  return { ok: true };
}

/* ---------------- Logs ---------------- */
export async function createLog(payload: {
  message: string;
  category_id: string | null;
  tags: string[];
  pinned: boolean;
}): Promise<LogEntry> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<LogEntry>('/api/logs', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }
  return callStaticRpc<LogEntry>('lb_create_log', {
    p_token: requireStaticToken(),
    p_message: payload.message,
    p_category_id: payload.category_id || null,
    p_tags: payload.tags,
    p_pinned: payload.pinned,
    p_created_at: null,
  });
}

export async function updateLog(
  id: string,
  payload: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean }
): Promise<LogEntry> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<LogEntry>(`/api/logs/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  }
  return callStaticRpc<LogEntry>('lb_update_log', {
    p_token: requireStaticToken(),
    p_id: id,
    p_message: payload.message ?? null,
    p_category_id: payload.category_id ?? null,
    p_clear_category: payload.category_id === null,
    p_tags: payload.tags ?? null,
    p_pinned: payload.pinned ?? null,
  });
}

export async function togglePinLog(id: string): Promise<LogEntry> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<LogEntry>(`/api/logs/${encodeURIComponent(id)}/toggle-pin`, {
      method: 'POST',
    });
  }
  return callStaticRpc<LogEntry>('lb_toggle_pin', {
    p_token: requireStaticToken(),
    p_id: id,
  });
}

export async function deleteLog(id: string): Promise<{ ok: boolean }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ ok: boolean }>(`/api/logs/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }
  await callStaticRpc<boolean>('lb_delete_log', {
    p_token: requireStaticToken(),
    p_id: id,
  });
  return { ok: true };
}

export async function bulkLogsAction(payload: {
  ids: string[];
  type: 'pin' | 'unpin' | 'delete' | 'category' | 'add_tag';
  category_id?: string | null;
  tag?: string;
}): Promise<{ affected: number }> {
  const cfg = await fetchConfig();
  if (cfg.bffEnabled) {
    return callBff<{ affected: number }>('/api/logs/bulk', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }
  const affected = await callStaticRpc<number>('lb_bulk_logs_action', {
    p_token: requireStaticToken(),
    p_ids: payload.ids,
    p_action: payload.type,
    p_category_id: payload.category_id ?? null,
    p_tag: payload.tag ?? null,
  });
  return { affected: affected ?? 0 };
}

/* ---------------- Export & Import ---------------- */
export async function downloadExportLogs(
  format: 'json' | 'csv',
  categories: Category[],
  filters: LogFilters
): Promise<void> {
  const cfg = await fetchConfig();
  let logs: LogEntry[];

  if (cfg.bffEnabled) {
    const params = new URLSearchParams({
      q: filters.q,
      categoryId: filters.categoryId,
      tags: filters.selectedTags.join(','),
      tagMatchMode: filters.tagMatchMode,
      dateFrom: filters.dateFrom,
      pinnedOnly: String(filters.pinnedOnly),
    });
    const res = await callBff<{ logs: LogEntry[] }>(`/api/logs/export?${params.toString()}`);
    logs = res.logs || [];
  } else {
    logs = await callStaticRpc<LogEntry[]>('lb_export_logs', {
      p_token: requireStaticToken(),
      p_q: filters.q,
      p_category_id: filters.categoryId || null,
      p_tags: filters.selectedTags,
      p_tag_match_mode: filters.tagMatchMode,
      p_date_from: filters.dateFrom || null,
      p_pinned_only: filters.pinnedOnly,
    });
  }

  const content = format === 'csv' ? serializeLogsToCSV(logs) : serializeLogsToJSON(logs, categories);
  const mime = format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8';
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `logbook-${new Date().toISOString().slice(0, 10)}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export async function importLogs(
  format: 'json' | 'csv',
  input: { file?: File; content?: string }
): Promise<ImportResult> {
  if (input.file && input.file.size > MAX_IMPORT_BYTES) {
    throw new ApiError('Import file exceeds 1 MB limit.', 400);
  }
  const raw = input.file ? await input.file.text() : input.content || '';
  if (!raw.trim()) {
    throw new ApiError('No import content provided.', 400);
  }
  if (new Blob([raw]).size > MAX_IMPORT_BYTES) {
    throw new ApiError('Import payload exceeds 1 MB limit.', 400);
  }

  const parsed = format === 'csv' ? parseImportCSV(raw) : parseImportJSON(raw);
  if (parsed.records.length === 0) {
    return {
      imported: 0,
      skipped: 0,
      failed: parsed.errors.length,
      errors: parsed.errors.slice(0, 20),
    };
  }
  if (parsed.records.length > MAX_IMPORT_RECORDS) {
    throw new ApiError(`Import is limited to ${MAX_IMPORT_RECORDS} records per request.`, 400);
  }

  const cfg = await fetchConfig();
  const res = cfg.bffEnabled
    ? await callBff<ImportResult>('/api/logs/import', {
        method: 'POST',
        body: JSON.stringify({ records: parsed.records }),
      })
    : await callStaticRpc<ImportResult>('lb_import_logs', {
        p_token: requireStaticToken(),
        p_records: parsed.records,
      });

  return {
    imported: res.imported || 0,
    skipped: res.skipped || 0,
    failed: (res.failed || 0) + parsed.errors.length,
    errors: [...parsed.errors, ...(res.errors || [])].slice(0, 20),
  };
}
