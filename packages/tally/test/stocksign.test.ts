import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkStockSignConvention, describeStockSignCheck } from '../src/stocksign.ts';

/**
 * The stock-sign decision table, exhaustively.
 *
 * The stakes: `stockCard` negates whatever the extraction hands it. If the extraction's
 * `$$IsDebit` premise fails in the field, every stock figure in the product renders negative.
 * These tests pin the mechanism that detects which world we are in — and, just as important,
 * pin the cells where the honest answer is "cannot tell", because collapsing "could not tell"
 * into either verdict is how a wrong sign ships with a green suite.
 */

/** Rows in the stockRequest schema: F01 name, F02 closing value. */
const rows = (...values: string[]) => values.map((v, i) => [`Group ${i}`, v]);

// ---------------------------------------------------------------- determined

test('both material and negative: the idiom matches the verified group idiom', () => {
  const check = checkStockSignConvention(rows('-4500000.00', '-1700000.00'), -6200000);
  assert.equal(check.verdict, 'dr_negative');
});

test('THE BUG THIS EXISTS FOR: material positive stock against a Dr-negative reference', () => {
  // The doubtful idiom returned positive magnitudes while the books' Stock-in-Hand — read
  // through the idiom the sign canary verified — says the same stock is a Dr (negative) asset.
  // $$IsDebit is not firing for StockGroup; the extraction must negate.
  const check = checkStockSignConvention(rows('4500000.00', '1700000.00'), -6200000);
  assert.equal(check.verdict, 'positive_magnitude');
});

test('a genuinely negative stock group does not flip the verdict when the net is decisive', () => {
  // Issue-before-receipt makes single groups negative in real books. The judgment is on the
  // NET — the very number stockCard totals — not on any single row.
  const check = checkStockSignConvention(rows('-4500000.00', '250000.00'), -4000000);
  assert.equal(check.verdict, 'dr_negative');
});

// ---------------------------------------------------------------- vacuous (nothing at risk)

test('no stock rows at all is unknown, not verified', () => {
  // A service business. Nothing is at risk today — but recording this as "verified ok" would
  // stop anyone ever re-asking, and the first stocked month would ship on an unverified sign.
  const check = checkStockSignConvention([], -6200000);
  assert.equal(check.verdict, 'unknown');
});

test('an immaterial stock sum is unknown even with a material reference', () => {
  const check = checkStockSignConvention(rows('0.40', '-0.20'), -6200000);
  assert.equal(check.verdict, 'unknown');
});

// ---------------------------------------------------------------- no trusted reference

test('TRI-STATE, the sharp cell: material stock with NO Stock-in-Hand row is unknown', () => {
  // A non-integrated book whose closing stock was never journalized, or a renamed reserved
  // group. One unverifiable signal must not flip an extraction: deciding 'positive_magnitude'
  // here from the stock rows alone would negate a correct extraction on any book whose
  // inventory legitimately nets negative.
  const check = checkStockSignConvention(rows('4500000.00'), undefined);
  assert.equal(check.verdict, 'unknown');
  // And the positive-looking sum must not be read as 'dr_negative' either.
  assert.equal(checkStockSignConvention(rows('-4500000.00'), undefined).verdict, 'unknown');
});

test('a zero Stock-in-Hand balance is "no reference", not "reference agrees with zero"', () => {
  const check = checkStockSignConvention(rows('4500000.00'), 0);
  assert.equal(check.verdict, 'unknown');
});

// ---------------------------------------------------------------- suspect reference

test('a CREDIT Stock-in-Hand balance disqualifies the reference instead of adjudicating', () => {
  // Held stock cannot structurally be a credit. A reference that violates its own structural
  // sign proves nothing by agreeing: with stock Σ positive and SIH positive, "same sign" would
  // read as verified via a broken ruler.
  assert.equal(checkStockSignConvention(rows('4500000.00'), 6200000).verdict, 'unknown');
  assert.equal(checkStockSignConvention(rows('-4500000.00'), 6200000).verdict, 'unknown');
});

// ---------------------------------------------------------------- evidence hygiene

test('malformed values are not evidence', () => {
  // Only the parseable row counts; it is material and negative against a good reference.
  const check = checkStockSignConvention(
    [['Cement', '-4500000.00'], ['Steel', 'not-a-number'], ['Paint', '']],
    -6200000,
  );
  assert.equal(check.verdict, 'dr_negative');
  assert.equal(check.stockSum, -4500000);
});

test('an all-malformed response is unknown, not zero-verified', () => {
  const check = checkStockSignConvention([['Cement', 'garbage']], -6200000);
  assert.equal(check.verdict, 'unknown');
});

test('a non-finite reference reading is treated as absent', () => {
  assert.equal(checkStockSignConvention(rows('4500000.00'), Number.NaN).verdict, 'unknown');
});

test('the evidence floor sits at one rupee, matching the group canary', () => {
  assert.equal(checkStockSignConvention(rows('-1.00'), -6200000).verdict, 'dr_negative');
  assert.equal(checkStockSignConvention(rows('-0.99'), -6200000).verdict, 'unknown');
  assert.equal(checkStockSignConvention(rows('-4500000.00'), -1).verdict, 'dr_negative');
  assert.equal(checkStockSignConvention(rows('-4500000.00'), -0.99).verdict, 'unknown');
});

// ---------------------------------------------------------------- support notes

test('every verdict describes itself, and the unknowns say WHICH unknown', () => {
  const vacuous = describeStockSignCheck(checkStockSignConvention([], undefined));
  assert.match(vacuous, /service business|no material inventory/i);

  const accountsOnly = describeStockSignCheck(checkStockSignConvention([], -6200000));
  assert.match(accountsOnly, /accounts-only|inventory module values ~0/i);

  const noReference = describeStockSignCheck(checkStockSignConvention(rows('4500000.00'), undefined));
  assert.match(noReference, /ASSUMED/);
  assert.match(noReference, /no material Stock-in-Hand/i);

  const suspect = describeStockSignCheck(checkStockSignConvention(rows('4500000.00'), 6200000));
  assert.match(suspect, /CREDIT|suspect/);

  const inverted = describeStockSignCheck(checkStockSignConvention(rows('4500000.00'), -6200000));
  assert.match(inverted, /POSITIVE magnitude/);
  assert.match(inverted, /negates/);
});
