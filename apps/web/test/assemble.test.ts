import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Section } from '@tally-bridge/core';
import { formatMoney } from '@tally-bridge/viewmodel';
import { assembleCompanyCards, type CompanySections } from '../src/data/assemble.ts';
import { AS_OF, GUID, cashPayload, companyPayload } from './helpers.ts';

/**
 * Decrypted payloads -> cards. Two properties matter here:
 *
 *   MONEY NEVER RIDES A FLOAT. `Amount` is a 2dp decimal STRING on the wire; the viewmodel
 *   parses it to integer paise and THROWS on anything else. A payload that smuggles a float in
 *   must cost that one card, never render a coerced number.
 *
 *   DISPLAY STRINGS ARE PRE-FORMATTED WITH INDIAN GROUPING, from `formatMoney` — never
 *   Intl.NumberFormat('en-IN'), which silently falls back to en-US grouping on runtimes
 *   without full ICU. The UI author renders `display` verbatim and does no formatting.
 */

const sections = (entries: Array<[Section, unknown]>): CompanySections => ({
  companyGuid: GUID,
  asOf: AS_OF,
  sections: new Map(entries),
});

test('cards carry Indian-grouped display strings the UI renders verbatim', () => {
  // ₹1,42,34,110 — 1.42 crore. en-US grouping would render ₹14,234,110, which is what
  // Intl('en-IN') silently degrades to without full ICU data. The wire value is Dr-negative.
  const { cards, failed } = assembleCompanyCards(
    sections([['cash_bank', cashPayload('-14234110.00')]]),
    () => {},
  );
  assert.equal(failed, false);
  assert.equal(cards.cashBank!.total.paise, 1423411000);
  assert.equal(cards.cashBank!.total.display, '₹1,42,34,110');
  assert.notEqual(cards.cashBank!.total.display, '₹14,234,110');
  assert.equal(cards.cashBank!.total.display, formatMoney(14234110));
});

test('MONEY NEVER FLOATS: a 3dp decimal, a Unicode minus, and garbage all cost the card, not a coercion', () => {
  for (const closing of ['1.005', '−342110.75' /* U+2212 */, 'NaN', '', '1,234.00', '1e3']) {
    const { cards, failed } = assembleCompanyCards(
      sections([
        ['cash_bank', { section: 'cash_bank', rows: [{ companyGuid: GUID, asOf: AS_OF, ledgerName: 'X', parent: 'Bank Accounts', closing }] }],
      ]),
      () => {},
    );
    assert.equal(failed, true, `closing=${JSON.stringify(closing)} must mark failure`);
    assert.equal(cards.cashBank, undefined, `closing=${JSON.stringify(closing)} must not render`);
  }
});

test('KNOWN COERCION, PINNED: a NUMBER closing whose String() form is <=2dp slips through parseAmountToPaise', () => {
  // MEASURED, not endorsed. `parseAmountToPaise` is typed (s: string) but its regex calls
  // exec(s), which coerces a number via String(). String(142341.1) is "142341.1" (shortest
  // round-trip form), so the float parses as 14234110 paise even though the float's true value
  // is 142341.09999999999854... — money routed through a float, losing sub-paisa silently.
  // Floats whose string form is not a plain <=2dp decimal (e.g. 0.1 + 0.2) still throw.
  //
  // Reachability is narrow: the payload is AEAD-sealed and device-signed, so only OUR OWN
  // writer (a buggy or future Bridge emitting numbers instead of canonical strings) can put a
  // number here — the wire contract says Amount is a string and the real Bridge honours it.
  // The desktop reader (apps/bridge/src/main/reader.ts) has the identical behaviour, since the
  // parse lives in packages/core, which this package does not own. Pinned so the day
  // parseAmountToPaise gains a typeof check, this test fails and gets deleted with a smile.
  const { cards, failed } = assembleCompanyCards(
    sections([
      ['cash_bank', { section: 'cash_bank', rows: [{ companyGuid: GUID, asOf: AS_OF, ledgerName: 'X', parent: 'Bank Accounts', closing: 142341.1 as unknown as string }] }],
    ]),
    () => {},
  );
  assert.equal(failed, false, 'if this starts failing, core gained a typeof guard: delete this test');
  assert.equal(cards.cashBank!.total.paise, -14234110);
});

test('one bad section does not blank the good ones', () => {
  const { cards, failed } = assembleCompanyCards(
    sections([
      ['cash_bank', cashPayload('-1234.50')],
      ['stock_value', { section: 'stock_value', rows: 'not an array' }],
    ]),
    () => {},
  );
  assert.equal(failed, true);
  assert.equal(cards.stock, undefined);
  assert.equal(cards.cashBank!.total.paise, 123450);
});

test('company name comes from the company section; the GUID is the honest fallback', () => {
  const named = assembleCompanyCards(
    sections([['company', companyPayload()], ['cash_bank', cashPayload('-1.00')]]),
    () => {},
  );
  assert.equal(named.cards.name, 'Acme Traders');

  const bare = assembleCompanyCards(sections([['cash_bank', cashPayload('-1.00')]]), () => {});
  assert.equal(bare.cards.name, GUID);
});

test('nothing throws out of assembleCompanyCards — failures are logged sentences, not stacks', () => {
  const logs: string[] = [];
  const { cards, failed } = assembleCompanyCards(
    sections([['cash_bank', null]]),
    (m) => logs.push(m),
  );
  assert.equal(failed, true);
  assert.equal(cards.cashBank, undefined);
  assert.equal(logs.length, 1);
  assert.ok(!logs[0]!.includes('\n    at '), 'log line must not carry a stack trace');
});
