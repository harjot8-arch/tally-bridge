import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseCompanies } from '../src/tally-detect.ts';

// A row is 8 fields (F01..F08): name, guid, altMst, altVch, booksFrom, lastVch, isActive(F07), state.
function company(name: string, guid: string, active: string): string {
  return (
    `<F01>${name}</F01><F02>${guid}</F02><F03>5</F03><F04>10</F04>` +
    `<F05>20230401</F05><F06>20260101</F06><F07>${active}</F07><F08>Maharashtra</F08>`
  );
}

test('parseCompanies maps rows to companies, F07 flags the active one', () => {
  const xml = `<ENVELOPE>${company('Acme Traders', 'guid-acme', '1')}${company('Beta Co', 'guid-beta', '0')}</ENVELOPE>`;
  const companies = parseCompanies(xml);
  assert.deepEqual(companies, [
    { guid: 'guid-acme', name: 'Acme Traders', isActive: true },
    { guid: 'guid-beta', name: 'Beta Co', isActive: false },
  ]);
});

test('a row with no GUID is skipped — GUID is identity, names are not', () => {
  // The middle company has an empty F02: it must not appear, and must not shift the others.
  const xml =
    `<ENVELOPE>${company('Acme', 'guid-acme', '1')}${company('Ghost', '', '0')}${company('Beta', 'guid-beta', '1')}</ENVELOPE>`;
  const companies = parseCompanies(xml);
  assert.equal(companies.length, 2);
  assert.deepEqual(
    companies.map((c) => c.guid),
    ['guid-acme', 'guid-beta'],
  );
});

test('an empty response yields no companies (Tally open, no company loaded)', () => {
  assert.deepEqual(parseCompanies('<ENVELOPE></ENVELOPE>'), []);
});
