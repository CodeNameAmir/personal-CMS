import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_IMPORT_BYTES,
  MAX_IMPORT_RECORDS,
  MAX_LOG_MESSAGE_LENGTH,
  MAX_TAGS_PER_LOG,
  computeLogStats,
  filterAndSortLogs,
  isValidHexColor,
  normalizeTagName,
  parseImportCSV,
  parseImportJSON,
  parseTagInput,
  safeHexColor,
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
  assert.equal(stats.total_categories, 2);
  assert.equal(stats.total_tags, 3);
  assert.equal(stats.by_tag[0].tag_name, 'prod');
  assert.equal(stats.by_tag[0].count, 2);
  assert.equal(stats.by_day.length, 30);
});

test('isValidHexColor and safeHexColor reject unsafe CSS values', () => {
  assert.equal(isValidHexColor('#3b82f6'), true);
  assert.equal(isValidHexColor(' #ABCDEF '), true);
  assert.equal(isValidHexColor('#fff'), false);
  assert.equal(isValidHexColor('red; background: url(https://evil.test)'), false);
  assert.equal(safeHexColor('expression(alert(1))'), '#64748b');
  assert.equal(safeHexColor(' #10b981 '), '#10b981');
});

test('serializeLogsToCSV neutralizes spreadsheet formula injection including leading whitespace', () => {
  const dangerousLogs: LogEntry[] = [
    {
      ...sampleLogs[0],
      id: 'log-formula-1',
      message: '=CMD("calc")',
      category_name: ' +SUM(A1:A2)',
    },
    {
      ...sampleLogs[0],
      id: 'log-formula-2',
      message: '\t@IMPORTXML("https://evil.test")',
      category_name: '-1+1',
    },
  ];
  const csv = serializeLogsToCSV(dangerousLogs);
  assert.match(csv, /"'=CMD\(""calc""\)"/);
  assert.match(csv, /' \+SUM\(A1:A2\)/);
  assert.match(csv, /'\t@IMPORTXML/);
  assert.match(csv, /'-1\+1/);
});

test('parseImportJSON and parseImportCSV enforce size, record count, message length, and tag caps', () => {
  const oversized = 'a'.repeat(MAX_IMPORT_BYTES + 10);
  assert.match(parseImportJSON(oversized).errors[0], /1 MB limit/);
  assert.match(parseImportCSV(oversized).errors[0], /1 MB limit/);

  const tooManyRecords = Array.from({ length: MAX_IMPORT_RECORDS + 1 }, (_, i) => ({ message: `row ${i}` }));
  assert.match(parseImportJSON(JSON.stringify(tooManyRecords)).errors[0], /limited to 500/);

  const manyTags = Array.from({ length: MAX_TAGS_PER_LOG + 10 }, (_, i) => `tag${i}`);
  const longMsg = 'x'.repeat(MAX_LOG_MESSAGE_LENGTH + 1);
  const res = parseImportJSON(
    JSON.stringify([
      { message: longMsg },
      { message: 'valid row', tags: manyTags },
    ])
  );
  assert.equal(res.records.length, 1);
  assert.equal(res.records[0].tags.length, MAX_TAGS_PER_LOG);
  assert.equal(res.errors.length, 1);
  assert.match(res.errors[0], /exceeds 10,000 characters/);
});

test('parseImportJSON and parseImportCSV strictly validate pinned booleans and created_at timestamps per row', () => {
  const jsonRes = parseImportJSON(
    JSON.stringify([
      { message: 'valid item', pinned: 'true', created_at: '2026-11-20T12:00:00.000Z' },
      { message: 'bad pinned item', pinned: 'maybe' },
      { message: 'bad date item', created_at: 'not-a-date' },
    ])
  );
  assert.equal(jsonRes.records.length, 1);
  assert.equal(jsonRes.records[0].pinned, true);
  assert.equal(jsonRes.errors.length, 2);
  assert.match(jsonRes.errors[0], /pinned/i);
  assert.match(jsonRes.errors[1], /created_at/i);

  const csvRes = parseImportCSV(
    [
      'message,category,tags,pinned,created_at',
      '"valid csv row","API","prod",false,"2026-11-20T12:00:00.000Z"',
      '"bad csv pinned","API","prod",invalid_bool,"2026-11-20T12:00:00.000Z"',
      '"bad csv date","API","prod",true,"invalid-date"',
    ].join('\n')
  );
  assert.equal(csvRes.records.length, 1);
  assert.equal(csvRes.records[0].pinned, false);
  assert.equal(csvRes.errors.length, 2);
  assert.match(csvRes.errors[0], /pinned/i);
  assert.match(csvRes.errors[1], /created_at/i);
});

