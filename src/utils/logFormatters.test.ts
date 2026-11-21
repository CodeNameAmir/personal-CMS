import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeLogStats,
  filterAndSortLogs,
  normalizeTagName,
  parseImportCSV,
  parseImportJSON,
  parseTagInput,
  serializeLogsToCSV,
  serializeLogsToJSON,
} from './logFormatters';
import type { Category, LogEntry, LogFilters } from '../types/logbook';

const sampleCategories: Category[] = [
  { id: 'cat-1', name: 'API', color: '#3b82f6', created_at: '2026-11-01T10:00:00.000Z' },
  { id: 'cat-2', name: 'Deployment', color: '#10b981', created_at: '2026-11-01T10:00:00.000Z' },
];

const sampleLogs: LogEntry[] = [
  {
    id: 'log-1',
    message: 'Nginx reverse proxy config updated',
    category_id: 'cat-2',
    category_name: 'Deployment',
    category_color: '#10b981',
    tags: [
      { id: 't1', name: 'nginx', color: '#3b82f6' },
      { id: 't2', name: 'prod', color: '#f59e0b' },
    ],
    pinned: false,
    attachment_name: null,
    attachment_path: null,
    attachment_size: null,
    created_at: '2026-11-20T12:00:00.000Z',
    updated_at: '2026-11-20T12:00:00.000Z',
  },
  {
    id: 'log-2',
    message: 'بکاپ گیری از سرویس احراز هویت انجام شد',
    category_id: 'cat-1',
    category_name: 'API',
    category_color: '#3b82f6',
    tags: [
      { id: 't2', name: 'prod', color: '#f59e0b' },
      { id: 't3', name: 'backup', color: '#10b981' },
    ],
    pinned: true,
    attachment_name: 'backup.txt',
    attachment_path: 'backup.txt',
    attachment_size: 2048,
    created_at: '2026-11-19T08:30:00.000Z',
    updated_at: '2026-11-19T08:30:00.000Z',
  },
];

const baseFilters: LogFilters = {
  q: '',
  categoryId: '',
  selectedTags: [],
  tagMatchMode: 'any',
  dateFrom: '',
  pinnedOnly: false,
  hasFileOnly: false,
};

test('normalizeTagName cleans hashtags, spaces, and preserves Persian letters', () => {
  assert.equal(normalizeTagName('  #Prod Server  '), 'prod-server');
  assert.equal(normalizeTagName('بکاپ_شبانه'), 'بکاپ_شبانه');
  assert.equal(normalizeTagName('###'), '');
});

test('parseTagInput splits and deduplicates tags', () => {
  assert.deepEqual(parseTagInput('nginx, #prod, nginx, ssl'), ['nginx', 'prod', 'ssl']);
});

test('filterAndSortLogs places pinned logs first and filters by multi-tag mode', () => {
  const sorted = filterAndSortLogs(sampleLogs, baseFilters);
  assert.equal(sorted[0].id, 'log-2');

  const matchAll = filterAndSortLogs(sampleLogs, {
    ...baseFilters,
    selectedTags: ['prod', 'nginx'],
    tagMatchMode: 'all',
  });
  assert.equal(matchAll.length, 1);
  assert.equal(matchAll[0].id, 'log-1');

  const matchAny = filterAndSortLogs(sampleLogs, {
    ...baseFilters,
    selectedTags: ['prod', 'nginx'],
    tagMatchMode: 'any',
  });
  assert.equal(matchAny.length, 2);

  const searchTag = filterAndSortLogs(sampleLogs, {
    ...baseFilters,
    q: 'backup',
  });
  assert.equal(searchTag.length, 1);
  assert.equal(searchTag[0].id, 'log-2');
});

test('CSV and JSON roundtrip preserves pinned status, category, and tags', () => {
  const csv = serializeLogsToCSV(sampleLogs);
  const parsedCsv = parseImportCSV(csv);
  assert.equal(parsedCsv.errors.length, 0);
  assert.equal(parsedCsv.records.length, 2);
  assert.equal(parsedCsv.records[1].pinned, true);
  assert.deepEqual(parsedCsv.records[0].tags, ['nginx', 'prod']);

  const json = serializeLogsToJSON(sampleLogs, sampleCategories);
  const parsedJson = parseImportJSON(json);
  assert.equal(parsedJson.errors.length, 0);
  assert.equal(parsedJson.records.length, 2);
  assert.equal(parsedJson.records[1].category, 'API');
});

test('computeLogStats calculates category, tag, and pinned totals accurately', () => {
  const stats = computeLogStats(sampleLogs, sampleCategories, new Date('2026-11-21T10:00:00.000Z'));
  assert.equal(stats.total_logs, 2);
  assert.equal(stats.pinned_logs, 1);
  assert.equal(stats.with_attachments, 1);
  assert.equal(stats.total_categories, 2);
  assert.equal(stats.total_tags, 3);
  assert.equal(stats.by_tag[0].tag_name, 'prod');
  assert.equal(stats.by_tag[0].count, 2);
  assert.equal(stats.by_day.length, 30);
});
