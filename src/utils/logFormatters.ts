import type { Category, DayStat, LogEntry, LogFilters, LogStats, TagStat } from '../types/logbook';

export const MAX_LOG_MESSAGE_LENGTH = 10_000;
export const MAX_CATEGORY_NAME_LENGTH = 64;
export const MAX_TAGS_PER_LOG = 25;
export const MAX_IMPORT_RECORDS = 500;
export const MAX_IMPORT_BYTES = 1024 * 1024;
export const MIN_PASSWORD_LENGTH = 6;
export const MAX_PASSWORD_LENGTH = 128;

const HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;

export function isValidHexColor(color: string): boolean {
  return HEX_COLOR_RE.test(color.trim());
}

export function safeHexColor(color: string | null | undefined, fallback = '#64748b'): string {
  if (!color) return fallback;
  const trimmed = color.trim();
  return HEX_COLOR_RE.test(trimmed) ? trimmed : fallback;
}

export const CATEGORY_PALETTE = [
  '#3b82f6',
  '#10b981',
  '#f59e0b',
  '#ec4899',
  '#8b5cf6',
  '#06b6d4',
  '#ef4444',
  '#84cc16',
  '#f97316',
  '#64748b',
];

export const TAG_PALETTE = [
  '#64748b',
  '#3b82f6',
  '#06b6d4',
  '#10b981',
  '#f59e0b',
  '#8b5cf6',
  '#ec4899',
  '#f97316',
];

/**
 * Normalizes a tag label to a clean lowercase slug-like token while preserving Unicode letters (e.g. Persian).
 */
export function normalizeTagName(raw: string): string {
  return raw
    .trim()
    .replace(/^#+/, '')
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^\p{L}\p{N}_-]+/gu, '')
    .slice(0, 32);
}

/**
 * Parses a comma or newline separated tag string into unique normalized tag names.
 */
export function parseTagInput(raw: string): string[] {
  const parts = raw
    .split(/[,\n]+/)
    .map((p) => normalizeTagName(p))
    .filter((p) => p.length > 0);
  return Array.from(new Set(parts));
}

/**
 * Picks a deterministic color for a tag name from TAG_PALETTE.
 */
export function defaultTagColor(name: string): string {
  let hash = 0;
  for (let i = 0; i < name.length; i += 1) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return TAG_PALETTE[hash % TAG_PALETTE.length];
}

/**
 * Filters and sorts logs: pinned first, then newest created_at descending.
 */
export function filterAndSortLogs(logs: LogEntry[], filters: LogFilters): LogEntry[] {
  const q = filters.q.trim().toLowerCase();
  const dateFromMs = filters.dateFrom ? new Date(`${filters.dateFrom}T00:00:00`).getTime() : null;
  const selectedTags = filters.selectedTags.map((t) => t.toLowerCase());

  const filtered = logs.filter((log) => {
    if (filters.pinnedOnly && !log.pinned) return false;
    if (filters.categoryId && log.category_id !== filters.categoryId) return false;

    if (dateFromMs !== null && !Number.isNaN(dateFromMs)) {
      const createdMs = new Date(log.created_at).getTime();
      if (createdMs < dateFromMs) return false;
    }

    if (selectedTags.length > 0) {
      const logTagSet = new Set(log.tags.map((t) => t.name.toLowerCase()));
      if (filters.tagMatchMode === 'all') {
        for (const tag of selectedTags) {
          if (!logTagSet.has(tag)) return false;
        }
      } else {
        const hasAny = selectedTags.some((tag) => logTagSet.has(tag));
        if (!hasAny) return false;
      }
    }

    if (q) {
      const inMessage = log.message.toLowerCase().includes(q);
      const inCategory = (log.category_name || '').toLowerCase().includes(q);
      const inTags = log.tags.some((t) => t.name.toLowerCase().includes(q));
      if (!inMessage && !inCategory && !inTags) return false;
    }

    return true;
  });

  return filtered.sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    const diff = new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    if (diff !== 0) return diff;
    return b.id.localeCompare(a.id);
  });
}

export interface ParsedImportRecord {
  message: string;
  category: string;
  tags: string[];
  pinned: boolean;
  created_at?: string;
}

/**
 * Parses JSON import payload (accepts either LogEntry[] or { logs: [...] }).
 */
export function parseImportJSON(content: string): { records: ParsedImportRecord[]; errors: string[] } {
  if (new Blob([content]).size > MAX_IMPORT_BYTES) {
    return { records: [], errors: ['Import payload exceeds 1 MB limit'] };
  }

  const errors: string[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return { records: [], errors: ['Invalid JSON syntax'] };
  }

  const rawItems = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Array.isArray((parsed as { logs?: unknown }).logs)
      ? (parsed as { logs: unknown[] }).logs
      : null;

  if (!rawItems) {
    return { records: [], errors: ['JSON must be an array of logs or an object with a "logs" array'] };
  }

  if (rawItems.length > MAX_IMPORT_RECORDS) {
    return {
      records: [],
      errors: [`Import is limited to ${MAX_IMPORT_RECORDS} records per request (found ${rawItems.length})`],
    };
  }

  const records: ParsedImportRecord[] = [];
  rawItems.forEach((item, idx) => {
    if (!item || typeof item !== 'object') {
      errors.push(`Row ${idx + 1}: expected an object`);
      return;
    }
    const obj = item as Record<string, unknown>;
    const message = typeof obj.message === 'string' ? obj.message.trim() : '';
    if (!message) {
      errors.push(`Row ${idx + 1}: missing message`);
      return;
    }
    if (message.length > MAX_LOG_MESSAGE_LENGTH) {
      errors.push(`Row ${idx + 1}: message exceeds ${MAX_LOG_MESSAGE_LENGTH.toLocaleString()} characters`);
      return;
    }
    const category =
      typeof obj.category_name === 'string' && obj.category_name.trim()
        ? obj.category_name.trim()
        : typeof obj.category === 'string' && obj.category.trim()
          ? obj.category.trim()
          : 'General';

    let tags: string[] = [];
    if (Array.isArray(obj.tags)) {
      tags = obj.tags
        .map((t) => {
          if (typeof t === 'string') return normalizeTagName(t);
          if (t && typeof t === 'object' && typeof (t as { name?: unknown }).name === 'string') {
            return normalizeTagName((t as { name: string }).name);
          }
          return '';
        })
        .filter(Boolean);
    } else if (typeof obj.tags === 'string') {
      tags = parseTagInput(obj.tags);
    }

    const uniqueTags = Array.from(new Set(tags)).slice(0, MAX_TAGS_PER_LOG);
    let pinned = false;
    if (obj.pinned !== undefined && obj.pinned !== null) {
      if (typeof obj.pinned === 'boolean') {
        pinned = obj.pinned;
      } else if (typeof obj.pinned === 'string' && (obj.pinned.toLowerCase() === 'true' || obj.pinned.toLowerCase() === 'false')) {
        pinned = obj.pinned.toLowerCase() === 'true';
      } else {
        errors.push(`Row ${idx + 1}: pinned must be a boolean`);
        return;
      }
    }

    let created_at: string | undefined;
    if (obj.created_at !== undefined && obj.created_at !== null && obj.created_at !== '') {
      if (typeof obj.created_at !== 'string' || Number.isNaN(new Date(obj.created_at).getTime())) {
        errors.push(`Row ${idx + 1}: invalid created_at timestamp`);
        return;
      }
      created_at = new Date(obj.created_at).toISOString();
    }

    records.push({
      message,
      category: category.slice(0, MAX_CATEGORY_NAME_LENGTH),
      tags: uniqueTags,
      pinned,
      created_at,
    });
  });

  return { records, errors };
}

/**
 * RFC-4180 compliant CSV parser supporting quoted fields, escaped quotes, and multiline values.
 */
export function parseCSVRows(csvText: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  const text = csvText.replace(/^\uFEFF/, '');

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        field += '"';
        i += 1;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\r' && next === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i += 1;
    } else if (ch === '\n' || ch === '\r') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows.filter((r) => r.some((cell) => cell.trim().length > 0));
}

export function parseImportCSV(content: string): { records: ParsedImportRecord[]; errors: string[] } {
  if (new Blob([content]).size > MAX_IMPORT_BYTES) {
    return { records: [], errors: ['Import payload exceeds 1 MB limit'] };
  }

  const rows = parseCSVRows(content);
  if (rows.length < 2) {
    return { records: [], errors: ['CSV must include a header row and at least one data row'] };
  }

  if (rows.length - 1 > MAX_IMPORT_RECORDS) {
    return {
      records: [],
      errors: [`Import is limited to ${MAX_IMPORT_RECORDS} records per request (found ${rows.length - 1})`],
    };
  }

  const headers = rows[0].map((h) => h.trim().toLowerCase());
  const msgIdx = headers.indexOf('message');
  if (msgIdx === -1) {
    return { records: [], errors: ['CSV header must include a "message" column'] };
  }

  const catIdx = headers.findIndex((h) => h === 'category' || h === 'category_name');
  const tagsIdx = headers.indexOf('tags');
  const pinnedIdx = headers.indexOf('pinned');
  const createdIdx = headers.indexOf('created_at');

  const records: ParsedImportRecord[] = [];
  const errors: string[] = [];

  for (let i = 1; i < rows.length; i += 1) {
    const row = rows[i];
    const message = (row[msgIdx] || '').trim();
    if (!message) {
      errors.push(`Row ${i + 1}: empty message`);
      continue;
    }
    if (message.length > MAX_LOG_MESSAGE_LENGTH) {
      errors.push(`Row ${i + 1}: message exceeds ${MAX_LOG_MESSAGE_LENGTH.toLocaleString()} characters`);
      continue;
    }

    const category = (catIdx >= 0 ? row[catIdx] : '')?.trim() || 'General';
    const rawTags = tagsIdx >= 0 ? row[tagsIdx] || '' : '';
    const tags = Array.from(
      new Set(
        rawTags
          .split(/[;|,]+/)
          .map((t) => normalizeTagName(t))
          .filter(Boolean)
      )
    ).slice(0, MAX_TAGS_PER_LOG);

    const pinnedRaw = pinnedIdx >= 0 ? (row[pinnedIdx] || '').trim().toLowerCase() : '';
    let pinned = false;
    if (pinnedRaw) {
      if (pinnedRaw === 'true' || pinnedRaw === '1' || pinnedRaw === 'yes') {
        pinned = true;
      } else if (pinnedRaw === 'false' || pinnedRaw === '0' || pinnedRaw === 'no') {
        pinned = false;
      } else {
        errors.push(`Row ${i + 1}: invalid pinned value`);
        continue;
      }
    }

    const rawDate = createdIdx >= 0 ? (row[createdIdx] || '').trim() : '';
    let created_at: string | undefined;
    if (rawDate) {
      if (Number.isNaN(new Date(rawDate).getTime())) {
        errors.push(`Row ${i + 1}: invalid created_at timestamp`);
        continue;
      }
      created_at = new Date(rawDate).toISOString();
    }

    records.push({
      message,
      category: category.slice(0, MAX_CATEGORY_NAME_LENGTH),
      tags,
      pinned,
      created_at,
    });
  }

  return { records, errors };
}

function escapeCSVCell(value: string): string {
  // Guard against spreadsheet formula injection on export (including leading whitespace)
  const safe = /^\s*[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  if (/[",\n\r]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function serializeLogsToCSV(logs: LogEntry[]): string {
  const header = ['id', 'category', 'tags', 'pinned', 'message', 'created_at', 'updated_at'];
  const lines = [header.join(',')];

  for (const log of logs) {
    const row = [
      log.id,
      log.category_name || 'General',
      log.tags.map((t) => t.name).join('; '),
      log.pinned ? 'true' : 'false',
      log.message,
      log.created_at,
      log.updated_at,
    ].map((cell) => escapeCSVCell(String(cell)));
    lines.push(row.join(','));
  }

  return lines.join('\n');
}

export function serializeLogsToJSON(logs: LogEntry[], categories: Category[]): string {
  return JSON.stringify(
    {
      exported_at: new Date().toISOString(),
      version: 1,
      categories: categories.map((c) => ({ name: c.name, color: c.color })),
      logs: logs.map((l) => ({
        id: l.id,
        category_name: l.category_name,
        category_color: l.category_color,
        tags: l.tags.map((t) => t.name),
        pinned: l.pinned,
        message: l.message,
        created_at: l.created_at,
        updated_at: l.updated_at,
      })),
    },
    null,
    2
  );
}

/**
 * Computes dashboard statistics without any log levels or file attachments.
 */
export function computeLogStats(logs: LogEntry[], categories: Category[], now = new Date()): LogStats {
  const catMap = new Map<string, { name: string; color: string; count: number }>();
  for (const cat of categories) {
    catMap.set(cat.id, { name: cat.name, color: cat.color, count: 0 });
  }

  const tagMap = new Map<string, { id: string; name: string; color: string; count: number }>();
  let pinnedCount = 0;

  // Build 30-day window buckets ending today
  const dayBuckets = new Map<string, number>();
  for (let i = 29; i >= 0; i -= 1) {
    const d = new Date(now);
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    dayBuckets.set(key, 0);
  }

  for (const log of logs) {
    if (log.pinned) pinnedCount += 1;

    if (log.category_id && catMap.has(log.category_id)) {
      catMap.get(log.category_id)!.count += 1;
    } else {
      const key = log.category_id || '__uncategorized__';
      const existing = catMap.get(key);
      if (existing) {
        existing.count += 1;
      } else {
        catMap.set(key, {
          name: log.category_name || 'Uncategorized',
          color: log.category_color || '#64748b',
          count: 1,
        });
      }
    }

    for (const tag of log.tags) {
      const existing = tagMap.get(tag.name);
      if (existing) {
        existing.count += 1;
      } else {
        tagMap.set(tag.name, { id: tag.id, name: tag.name, color: tag.color, count: 1 });
      }
    }

    const dayKey = log.created_at.slice(0, 10);
    if (dayBuckets.has(dayKey)) {
      dayBuckets.set(dayKey, (dayBuckets.get(dayKey) || 0) + 1);
    }
  }

  const by_category = Array.from(catMap.entries())
    .map(([category_id, v]) => ({
      category_id,
      category_name: v.name,
      category_color: v.color,
      count: v.count,
    }))
    .filter((c) => c.count > 0)
    .sort((a, b) => b.count - a.count);

  const by_tag: TagStat[] = Array.from(tagMap.values())
    .map((t) => ({
      tag_id: t.id,
      tag_name: t.name,
      tag_color: t.color,
      count: t.count,
    }))
    .sort((a, b) => b.count - a.count);

  const by_day: DayStat[] = Array.from(dayBuckets.entries()).map(([day, count]) => ({ day, count }));

  return {
    total_logs: logs.length,
    pinned_logs: pinnedCount,
    total_categories: categories.length,
    total_tags: tagMap.size,
    by_category,
    by_tag,
    by_day,
  };
}

export function formatRelativeTime(iso: string, nowMs = Date.now()): string {
  const ms = new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const diffSec = Math.floor((nowMs - ms) / 1000);
  if (diffSec < 60) return diffSec <= 1 ? 'just now' : `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 604800) {
    const days = Math.floor(diffSec / 86400);
    return days === 1 ? 'yesterday' : `${days}d ago`;
  }
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export function formatExactTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
