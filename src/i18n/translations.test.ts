import test from 'node:test';
import assert from 'node:assert/strict';
import { getTranslator, translations } from './translations';

test('English and Persian translation dictionaries have identical keys', () => {
  const enKeys = Object.keys(translations.en).sort();
  const faKeys = Object.keys(translations.fa).sort();
  assert.deepEqual(faKeys, enKeys);
  for (const key of faKeys) {
    assert.ok(
      translations.fa[key as keyof typeof translations.fa].trim().length > 0,
      `Missing Persian translation for ${key}`
    );
  }
});

test('getTranslator returns localized strings for both languages', () => {
  const tEn = getTranslator('en');
  const tFa = getTranslator('fa');
  assert.equal(tEn('allLogs'), 'All Logs');
  assert.equal(tFa('allLogs'), 'همه لاگ‌ها');
});
