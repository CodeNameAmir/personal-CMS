import type {
  ApiTokenRecord,
  AppConfig,
  Category,
  CreatedApiToken,
  DbMode,
  ImportResult,
  LogEntry,
  LogFilters,
  LogStats,
  Tag,
  UserSession,
} from '../types/logbook';

let inMemoryToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

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

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (inMemoryToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${inMemoryToken}`);
  }
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(url, { ...options, headers });
  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await res.json() : null;

  if (!res.ok) {
    if (res.status === 401 && unauthorizedHandler && !url.startsWith('/api/auth/login') && !url.startsWith('/api/webhook')) {
      unauthorizedHandler();
    }
    throw new ApiError(
      (data && data.error) || res.statusText || 'Request failed',
      res.status,
      data?.code
    );
  }

  return data as T;
}

export function fetchConfig(): Promise<AppConfig> {
  return request<AppConfig>('/api/config');
}

export function fetchSupabaseSchema(): Promise<{ sql: string }> {
  return request<{ sql: string }>('/api/supabase-schema');
}

export async function login(payload: {
  username: string;
  password: string;
  db_mode: DbMode;
}): Promise<{ token: string; user: UserSession }> {
  const res = await request<{ token: string; user: UserSession }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  setAuthToken(res.token);
  return res;
}

export function signup(payload: {
  username: string;
  password: string;
  db_mode: DbMode;
}): Promise<{ user: UserSession }> {
  return request('/api/auth/signup', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function logout(): Promise<void> {
  try {
    await request('/api/auth/logout', { method: 'POST' });
  } finally {
    setAuthToken(null);
  }
}

export function changePassword(currentPassword: string, newPassword: string): Promise<{ ok: boolean }> {
  return request('/api/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

/* ---------------- API Tokens & Webhook ---------------- */
export function listApiTokens(): Promise<ApiTokenRecord[]> {
  return request<ApiTokenRecord[]>('/api/tokens');
}

export function createApiToken(name: string): Promise<CreatedApiToken> {
  return request<CreatedApiToken>('/api/tokens', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

export function deleteApiToken(id: string): Promise<{ ok: boolean }> {
  return request(`/api/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function sendWebhookLog(
  rawToken: string,
  payload: { message: string; category?: string; tags?: string[]; pinned?: boolean }
): Promise<{ log: LogEntry }> {
  return request<{ log: LogEntry }>('/api/webhook/logs', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${rawToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
}

/* ---------------- Categories ---------------- */
export function listCategories(): Promise<Category[]> {
  return request<Category[]>('/api/categories');
}

export function createCategory(name: string, color: string): Promise<Category> {
  return request<Category>('/api/categories', {
    method: 'POST',
    body: JSON.stringify({ name, color }),
  });
}

export function updateCategory(id: string, name: string, color: string): Promise<Category> {
  return request<Category>(`/api/categories/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify({ name, color }),
  });
}

export function deleteCategory(id: string): Promise<{ ok: boolean }> {
  return request(`/api/categories/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/* ---------------- Tags ---------------- */
export function listTags(): Promise<Tag[]> {
  return request<Tag[]>('/api/tags');
}

export function createTag(name: string, color?: string): Promise<Tag> {
  return request<Tag>('/api/tags', {
    method: 'POST',
    body: JSON.stringify({ name, color }),
  });
}

export function updateTag(id: string, name: string, color: string): Promise<Tag> {
  return request<Tag>(`/api/tags/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify({ name, color }),
  });
}

export function deleteTag(id: string): Promise<{ ok: boolean }> {
  return request(`/api/tags/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/* ---------------- Logs ---------------- */
function buildFilterParams(filters: LogFilters): URLSearchParams {
  const qs = new URLSearchParams();
  if (filters.q.trim()) qs.set('q', filters.q.trim());
  if (filters.categoryId) qs.set('category_id', filters.categoryId);
  if (filters.selectedTags.length > 0) qs.set('tags', filters.selectedTags.join(','));
  if (filters.selectedTags.length > 1) qs.set('tag_mode', filters.tagMatchMode);
  if (filters.dateFrom) qs.set('date_from', filters.dateFrom);
  if (filters.pinnedOnly) qs.set('pinned', 'true');
  if (filters.hasFileOnly) qs.set('has_file', 'true');
  return qs;
}

export function listLogs(
  filters: LogFilters,
  limit = 20,
  offset = 0
): Promise<{ logs: LogEntry[]; total: number; total_unfiltered: number }> {
  const qs = buildFilterParams(filters);
  qs.set('limit', String(limit));
  qs.set('offset', String(offset));
  return request(`/api/logs?${qs.toString()}`);
}

export function createLog(payload: {
  message: string;
  category_id: string | null;
  tags: string[];
  pinned: boolean;
}): Promise<LogEntry> {
  return request<LogEntry>('/api/logs', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function updateLog(
  id: string,
  payload: { message?: string; category_id?: string | null; tags?: string[]; pinned?: boolean }
): Promise<LogEntry> {
  return request<LogEntry>(`/api/logs/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export function togglePinLog(id: string): Promise<LogEntry> {
  return request<LogEntry>(`/api/logs/${encodeURIComponent(id)}/pin`, { method: 'POST' });
}

export function deleteLog(id: string): Promise<{ ok: boolean }> {
  return request(`/api/logs/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function bulkLogsAction(payload: {
  ids: string[];
  type: 'pin' | 'unpin' | 'delete' | 'category' | 'add_tag';
  category_id?: string | null;
  tag?: string;
}): Promise<{ affected: number }> {
  return request('/api/logs/bulk', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function uploadLogAttachment(logId: string, file: File): Promise<{ log: LogEntry }> {
  const fd = new FormData();
  fd.append('file', file);
  return request<{ log: LogEntry }>(`/api/logs/${encodeURIComponent(logId)}/attachment`, {
    method: 'POST',
    body: fd,
  });
}

export function deleteLogAttachment(logId: string): Promise<{ log: LogEntry }> {
  return request<{ log: LogEntry }>(`/api/logs/${encodeURIComponent(logId)}/attachment`, {
    method: 'DELETE',
  });
}

export async function downloadLogAttachment(logId: string, filename: string): Promise<void> {
  const headers = new Headers();
  if (inMemoryToken) headers.set('Authorization', `Bearer ${inMemoryToken}`);
  const res = await fetch(`/api/logs/${encodeURIComponent(logId)}/attachment`, { headers });
  if (!res.ok) throw new Error('Download failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function fetchStats(): Promise<LogStats> {
  return request<LogStats>('/api/stats');
}

export async function exportLogs(format: 'json' | 'csv', filters: LogFilters): Promise<void> {
  const qs = buildFilterParams(filters);
  qs.set('format', format);
  const headers = new Headers();
  if (inMemoryToken) headers.set('Authorization', `Bearer ${inMemoryToken}`);
  const res = await fetch(`/api/export?${qs.toString()}`, { headers });
  if (!res.ok) throw new Error('Export failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `logbook-${new Date().toISOString().slice(0, 10)}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function importLogs(
  format: 'json' | 'csv',
  input: { file?: File; content?: string }
): Promise<ImportResult> {
  if (input.file) {
    const fd = new FormData();
    fd.append('file', input.file);
    return request<ImportResult>(`/api/import?format=${format}`, {
      method: 'POST',
      body: fd,
    });
  }
  return request<ImportResult>(`/api/import?format=${format}`, {
    method: 'POST',
    body: JSON.stringify({ content: input.content || '' }),
  });
}
