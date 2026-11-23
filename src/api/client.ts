import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import type {
  ApiTokenRecord,
  AppConfig,
  Category,
  CreatedApiToken,
  ImportResult,
  LogEntry,
  LogFilters,
  Tag,
  UserSession,
} from '../types/logbook';
import {
  filterAndSortLogs,
  parseImportCSV,
  parseImportJSON,
  serializeLogsToCSV,
  serializeLogsToJSON,
} from '../utils/logFormatters';
import { SUPABASE_SETUP_SQL } from './supabaseSchema';

let inMemoryToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

let cachedConfig: AppConfig | null = null;
let cachedClient: SupabaseClient | null = null;

export function setAuthToken(token: string | null): void {
  inMemoryToken = token;
}

export function getAuthToken(): string | null {
  return inMemoryToken;
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
    supabaseUrl,
    supabasePublishableKey,
    supabaseConfigured: Boolean(supabaseUrl && supabasePublishableKey),
  };
}

export async function fetchConfig(): Promise<AppConfig> {
  if (cachedConfig) return cachedConfig;

  const buildCfg = getBuildTimeConfig();
  if (buildCfg.supabaseConfigured) {
    cachedConfig = buildCfg;
    return cachedConfig;
  }

  // Fallback for preview servers where secrets are configured server-side without VITE_ prefix
  try {
    const res = await fetch('/api/config');
    const contentType = res.headers.get('content-type') || '';
    if (res.ok && contentType.includes('application/json')) {
      const data = (await res.json()) as Partial<AppConfig>;
      const url = (data.supabaseUrl || '').trim();
      const key = (data.supabasePublishableKey || '').trim();
      cachedConfig = {
        supabaseUrl: url,
        supabasePublishableKey: key,
        supabaseConfigured: Boolean(url && key),
      };
      return cachedConfig;
    }
  } catch {
    // Static hosts (GitHub Pages) will not have /api/config
  }

  cachedConfig = buildCfg;
  return cachedConfig;
}

export function getLoadedConfig(): AppConfig {
  return cachedConfig || getBuildTimeConfig();
}

export async function fetchSupabaseSchema(): Promise<{ sql: string }> {
  return { sql: SUPABASE_SETUP_SQL };
}

async function getClient(): Promise<{ client: SupabaseClient; config: AppConfig }> {
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
  err: { message?: string; code?: string; details?: string } | null,
  options: { triggerUnauthorized?: boolean } = {}
): never {
  const msg = err?.message || 'Supabase request failed';
  const code = err?.code || '';

  if (msg.includes('UNAUTHORIZED:')) {
    const clean = msg.replace(/^.*UNAUTHORIZED:\s*/i, '').trim() || 'Session expired or invalid.';
    if (options.triggerUnauthorized && unauthorizedHandler) {
      inMemoryToken = null;
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

async function callRpc<T>(
  fn: string,
  params: Record<string, unknown>,
  options: { triggerUnauthorized?: boolean } = { triggerUnauthorized: true }
): Promise<T> {
  const { client } = await getClient();
  const { data, error } = await client.rpc(fn, params);
  if (error) {
    mapRpcError(error, options);
  }
  return data as T;
}

function requireToken(): string {
  if (!inMemoryToken) {
    if (unauthorizedHandler) unauthorizedHandler();
    throw new ApiError('Missing session token', 401, 'UNAUTHORIZED');
  }
  return inMemoryToken;
}

/* ---------------- Auth ---------------- */
export async function login(payload: {
  username: string;
  password: string;
}): Promise<{ token: string; user: UserSession }> {
  const res = await callRpc<{ token: string; user: UserSession }>(
    'lb_login',
    {
      p_username: payload.username,
      p_password: payload.password,
    },
    { triggerUnauthorized: false }
  );
  setAuthToken(res.token);
  return res;
}

export async function signup(payload: {
  username: string;
  password: string;
}): Promise<{ token: string; user: UserSession }> {
  const res = await callRpc<{ token: string; user: UserSession }>(
    'lb_signup',
    {
      p_username: payload.username,
      p_password: payload.password,
    },
    { triggerUnauthorized: false }
  );
  setAuthToken(res.token);
  return res;
}

export async function logout(): Promise<void> {
  const token = inMemoryToken;
  setAuthToken(null);
  if (!token) return;
  try {
    await callRpc<boolean>('lb_logout', { p_token: token }, { triggerUnauthorized: false });
  } catch {
    // ignore errors during sign out
  }
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  await callRpc<boolean>('lb_change_password', {
    p_token: requireToken(),
    p_current_password: currentPassword,
    p_new_password: newPassword,
  });
  return { ok: true };
}

/* ---------------- Workspace Snapshot ---------------- */
export interface WorkspaceSnapshot {
  categories: Category[];
  tags: Tag[];
  logs: LogEntry[];
}

export function fetchWorkspace(): Promise<WorkspaceSnapshot> {
  return callRpc<WorkspaceSnapshot>('lb_get_workspace', {
    p_token: requireToken(),
  });
}

/* ---------------- API Tokens & Webhook ---------------- */
export function listApiTokens(): Promise<ApiTokenRecord[]> {
  return callRpc<ApiTokenRecord[]>('lb_list_api_tokens', {
    p_token: requireToken(),
  });
}

export function createApiToken(name: string): Promise<CreatedApiToken> {
  return callRpc<CreatedApiToken>('lb_create_api_token', {
    p_token: requireToken(),
    p_name: name,
  });
}

export async function deleteApiToken(id: string): Promise<{ ok: boolean }> {
  await callRpc<boolean>('lb_delete_api_token', {
    p_token: requireToken(),
    p_id: id,
  });
  return { ok: true };
}

export async function sendWebhookLog(
  rawToken: string,
  payload: { message: string; category?: string; tags?: string[]; pinned?: boolean }
): Promise<{ log: LogEntry }> {
  const cfg = await fetchConfig();
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
export function createCategory(name: string, color: string): Promise<Category> {
  return callRpc<Category>('lb_create_category', {
    p_token: requireToken(),
    p_name: name,
    p_color: color,
  });
}

export function updateCategory(id: string, name: string, color: string): Promise<Category> {
  return callRpc<Category>('lb_update_category', {
    p_token: requireToken(),
    p_id: id,
    p_name: name,
    p_color: color,
  });
}

export async function deleteCategory(id: string): Promise<{ ok: boolean }> {
  await callRpc<boolean>('lb_delete_category', {
    p_token: requireToken(),
    p_id: id,
  });
  return { ok: true };
}

/* ---------------- Tags ---------------- */
export function createTag(name: string, color?: string): Promise<Tag> {
  return callRpc<Tag>('lb_create_or_get_tag', {
    p_token: requireToken(),
    p_name: name,
    p_color: color || null,
  });
}

export function updateTag(id: string, name: string, color: string): Promise<Tag> {
  return callRpc<Tag>('lb_update_tag', {
    p_token: requireToken(),
    p_id: id,
    p_name: name,
    p_color: color,
  });
}

export async function deleteTag(id: string): Promise<{ ok: boolean }> {
  await callRpc<boolean>('lb_delete_tag', {
    p_token: requireToken(),
    p_id: id,
  });
  return { ok: true };
}

/* ---------------- Logs ---------------- */
export function createLog(payload: {
  message: string;
  category_id: string | null;
  tags: string[];
  pinned: boolean;
}): Promise<LogEntry> {
  return callRpc<LogEntry>('lb_create_log', {
    p_token: requireToken(),
    p_message: payload.message,
    p_category_id: payload.category_id || null,
    p_tags: payload.tags,
    p_pinned: payload.pinned,
    p_created_at: null,
  });
}

export function updateLog(
  id: string,
  payload: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean }
): Promise<LogEntry> {
  return callRpc<LogEntry>('lb_update_log', {
    p_token: requireToken(),
    p_id: id,
    p_message: payload.message ?? null,
    p_category_id: payload.category_id ?? null,
    p_clear_category: payload.category_id === null,
    p_tags: payload.tags ?? null,
    p_pinned: payload.pinned ?? null,
  });
}

export function togglePinLog(id: string): Promise<LogEntry> {
  return callRpc<LogEntry>('lb_toggle_pin', {
    p_token: requireToken(),
    p_id: id,
  });
}

export async function deleteLog(id: string): Promise<{ ok: boolean }> {
  await callRpc<boolean>('lb_delete_log', {
    p_token: requireToken(),
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
  const affected = await callRpc<number>('lb_bulk_logs_action', {
    p_token: requireToken(),
    p_ids: payload.ids,
    p_action: payload.type,
    p_category_id: payload.category_id ?? null,
    p_tag: payload.tag ?? null,
  });
  return { affected: affected ?? 0 };
}

/* ---------------- Export & Import ---------------- */
export function downloadExportLogs(
  format: 'json' | 'csv',
  logs: LogEntry[],
  categories: Category[],
  filters: LogFilters
): void {
  const filtered = filterAndSortLogs(logs, filters);
  const content =
    format === 'csv' ? serializeLogsToCSV(filtered) : serializeLogsToJSON(filtered, categories);
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
  const raw = input.file ? await input.file.text() : input.content || '';
  if (!raw.trim()) {
    throw new ApiError('No import content provided.', 400);
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

  const res = await callRpc<ImportResult>('lb_import_logs', {
    p_token: requireToken(),
    p_records: parsed.records,
  });

  return {
    imported: res.imported || 0,
    skipped: res.skipped || 0,
    failed: (res.failed || 0) + parsed.errors.length,
    errors: [...parsed.errors, ...(res.errors || [])].slice(0, 20),
  };
}
