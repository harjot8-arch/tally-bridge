import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkGroupSignConvention, describeSignCheck } from '../src/signs.ts';

/**
 * The canary for the highest-value unverifiable in the product.
 *
 * `expr.amount` assumes `$$NumValue` returns a MAGNITUDE. If it is already signed, every number
 * inverts and nothing errors. Only a real Tally settles that — these tests do not pretend to.
 * They pin that a real book, when we finally meet one, gets to SAY SO.
 */

/** groupsRequest schema: F01 name, F02 parent, F03 primary, F04 revenue, F05 open, F06 close. */
const g = (name: string, closing: string) => [name, 'Primary', name, '0', '0.00', closing, '0'];

test('a correctly-signed book reads as ok', () => {
  // Dr negative, Cr positive: cash is an asset and arrives NEGATIVE; sales accrue credit.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '-125000.00'),
    g('Sales Accounts', '500000.00'),
  ]);
  assert.equal(check.verdict, 'ok');
  assert.deepEqual(check.agreed, ['Cash-in-Hand', 'Sales Accounts']);
});

test('THE CANARY: a globally inverted book is caught', () => {
  // What the world looks like if $$NumValue is signed: every debit double-negated. Cash reads
  // positive, sales read negative. The dashboard would be confident and inside-out.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '125000.00'),
    g('Fixed Assets', '900000.00'),
    g('Sales Accounts', '-500000.00'),
    g('Purchase Accounts', '300000.00'),
  ]);
  assert.equal(check.verdict, 'inverted');
  assert.equal(check.agreed.length, 0);
  assert.match(describeSignCheck(check), /signs are WRONG/);
});

/**
 * The two hypotheses that actually matter.
 *
 * `expr.amount` negates on the DEBIT BRANCH ONLY, so a signed `$$NumValue` never inverts the
 * whole book — it collapses it onto ONE sign, taking out exactly one side. A canary that waits
 * for "everything inverted" waits for a world that cannot happen and misses both of these.
 */

test('H1: a signed $$NumValue with internal Dr=+ makes every CREDIT negative', () => {
  // Dr -> -x, Cr -> -x: the whole book goes negative. Cash is right by accident, which is
  // exactly why "at least one signal agrees" cannot be allowed to veto the verdict.
  //
  // This is the hypothesis the reference implementation's "(-)"-rewrite argument does NOT rule
  // out — under H1 both branches go negative, so that rewrite is fully live. It is the likeliest
  // way this product ships inside-out, and it must be caught.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '-125000.00'), // agrees, by luck
    g('Fixed Assets', '-900000.00'), // agrees, by luck
    g('Sales Accounts', '-500000.00'), // WRONG
    g('Direct Income', '-40000.00'), // WRONG
    g('Indirect Income', '-10000.00'), // WRONG
  ]);
  assert.equal(check.verdict, 'inverted');
  assert.deepEqual(check.disagreed, ['Sales Accounts', 'Direct Income', 'Indirect Income']);
  assert.ok(check.agreed.length > 0, 'signals agreeing must NOT veto a whole class being wrong');
});

test('H2: a signed $$NumValue with internal Dr=- makes every DEBIT positive', () => {
  // Dr -> +x, Cr -> +x: the whole book goes positive, and sales are right by accident.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '125000.00'), // WRONG
    g('Fixed Assets', '900000.00'), // WRONG
    g('Purchase Accounts', '300000.00'), // WRONG
    g('Sales Accounts', '500000.00'), // agrees, by luck
  ]);
  assert.equal(check.verdict, 'inverted');
  assert.ok(check.agreed.includes('Sales Accounts'));
});

test('a whole class must be wrong — one dissenter inside a class is a BOOK problem', () => {
  // The line between "your arithmetic is broken" and "your data entry is odd". Cash is credit
  // (a real, ordinary error) but the other debit-normal groups are fine, so the debit side as a
  // CLASS is not broken and there is nothing to accuse.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '5000.00'), // wrong
    g('Fixed Assets', '-900000.00'), // right
    g('Purchase Accounts', '-300000.00'), // right
    g('Sales Accounts', '500000.00'), // right
    g('Direct Income', '40000.00'), // right
  ]);
  assert.equal(check.verdict, 'unknown');
});

test('a legitimately returns-heavy month is not condemned', () => {
  // Net sales CAN be a debit — a month of credit notes. On its own that is one signal in the
  // credit class, below the two-signal bar, so it cannot convict.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '-125000.00'),
    g('Fixed Assets', '-900000.00'),
    g('Sales Accounts', '-20000.00'),
  ]);
  assert.equal(check.verdict, 'unknown');
});

test('the balance-sheet identity would NOT have caught it, which is why this exists', () => {
  // The tempting invariant is `Σ closing ≈ 0`. It is invariant under a global sign flip, so it
  // passes identically in both worlds and distinguishes nothing. Demonstrated rather than argued.
  const book = [g('Cash-in-Hand', '-125000.00'), g('Capital Account', '125000.00')];
  const inverted = book.map((r) => [...r.slice(0, 5), String(-Number(r[5])), r[6]!]);
  const sum = (rows: string[][]) => rows.reduce((a, r) => a + Number(r[5]), 0);
  assert.equal(sum(book), 0);
  assert.equal(sum(inverted), 0, 'both books balance — the identity is blind to inversion');
  // The known-sign check is not blind.
  assert.equal(checkGroupSignConvention(book).verdict, 'ok');
  assert.notEqual(checkGroupSignConvention(inverted).verdict, 'ok');
});

test('ONE weird group cannot condemn a working install', () => {
  // A credit cash balance is a real data-entry error that real books contain. Inversion is global
  // by construction, so a single dissenter with the rest agreeing is a book problem, not a sign
  // problem — and refusing to sync over it would be a false accusation.
  const check = checkGroupSignConvention([
    g('Cash-in-Hand', '5000.00'), // wrong way round
    g('Sales Accounts', '500000.00'), // right way round
    g('Fixed Assets', '-900000.00'), // right way round
  ]);
  assert.equal(check.verdict, 'unknown');
  assert.deepEqual(check.disagreed, ['Cash-in-Hand']);
  assert.match(describeSignCheck(check), /evidence conflicts/);
});

test('one inverted signal alone is not enough', () => {
  // The bar is two independent signals, because the cost of a false positive is refusing to
  // configure a working install.
  const check = checkGroupSignConvention([g('Cash-in-Hand', '125000.00')]);
  assert.equal(check.verdict, 'unknown');
});

test('an empty or brand-new book says "unknown", never "inverted"', () => {
  assert.equal(checkGroupSignConvention([]).verdict, 'unknown');
  assert.equal(
    checkGroupSignConvention([g('Cash-in-Hand', '0.00'), g('Sales Accounts', '0.00')]).verdict,
    'unknown',
  );
  // Sub-rupee balances are rounding, not evidence.
  assert.equal(
    checkGroupSignConvention([g('Cash-in-Hand', '0.40'), g('Sales Accounts', '-0.30')]).verdict,
    'unknown',
  );
  assert.match(describeSignCheck(checkGroupSignConvention([])), /no reserved group carried/);
});

test('groups whose sign is a matter of opinion are excluded', () => {
  // Sundry Debtors flips on a large advance; Capital Account flips on accumulated losses; a bank
  // account flips on an overdraft. None of them is evidence about ARITHMETIC.
  const check = checkGroupSignConvention([
    g('Sundry Debtors', '130000.00'),
    g('Capital Account', '-500000.00'),
    g('Bank Accounts', '342110.75'),
  ]);
  assert.equal(check.verdict, 'unknown');
  assert.deepEqual(check.disagreed, [], 'no opinion may be counted as a signal');
});

test('a renamed reserved group yields silence, not a false accusation', () => {
  const check = checkGroupSignConvention([g('Petty Cash Box', '125000.00')]);
  assert.equal(check.verdict, 'unknown');
});

test('the canary never throws, whatever the book contains', () => {
  // It is a canary, not an extractor. If it can throw, it becomes the outage.
  for (const closing of ['', 'garbage', 'Infinity', '-Infinity', 'NaN', '1e400', '&#4;']) {
    assert.doesNotThrow(() => checkGroupSignConvention([g('Cash-in-Hand', closing)]), closing);
    assert.equal(checkGroupSignConvention([g('Cash-in-Hand', closing)]).verdict, 'unknown', closing);
  }
  assert.doesNotThrow(() => checkGroupSignConvention([[], ['x']]));
});

test('sub-groups do not impersonate the reserved group they sit under', () => {
  // Matched exactly: "Cash-in-Hand (Branch)" is a user group and its sign is the user's business.
  const check = checkGroupSignConvention([g('Cash-in-Hand (Branch)', '125000.00')]);
  assert.equal(check.verdict, 'unknown');
});
