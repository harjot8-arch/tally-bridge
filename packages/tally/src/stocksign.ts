/**
 * The stock-sign probe: does `expr.amount('$ClosingValue')` behave on a StockGroup?
 *
 * ## The doubtful premise this resolves
 *
 * `expr.amount` is `if $$IsDebit:X then -$$NumValue:X else $$NumValue:X`. On a Group's
 * `$ClosingBalance` that idiom is guarded by the sign canary in signs.ts. A StockGroup's
 * `$ClosingValue` is a different animal: a computed inventory valuation, not a ledger balance
 * with a Dr/Cr side. Whether `$$IsDebit` is even meaningful for it — let alone TRUE — cannot be
 * settled from a desk. If it silently evaluates false, the idiom returns a POSITIVE magnitude,
 * `stockCard`'s display flip then negates it, and every stock figure in the product renders
 * negative. Two independent sign decisions that must agree, with nothing checking that they do.
 * This file is the check.
 *
 * ## The oracle: the Stock-in-Hand group, SIGN only
 *
 * Tally's reserved chart of accounts has a `Stock-in-Hand` group, and its closing balance is
 * the books' closing stock. It arrives through the GROUP request — the idiom the sign canary
 * has already validated by the time this runs. Both readings describe the same economic
 * quantity (the value of stock held), so comparing their SIGNS directly tests whether the stock
 * idiom resolves Dr/Cr the way the verified group idiom does — without needing to know the true
 * sign of the inventory itself.
 *
 * Signs only, never magnitudes: when "Integrate Accounts and Inventory" is OFF, the
 * Stock-in-Hand balance is whatever closing-stock value the accountant last journalized, and it
 * legitimately differs from the inventory module's valuation. A magnitude comparison would
 * declare an honest book contradictory. (That configuration claim about Tally is from training
 * knowledge, not measured here; the design only leans on it in the direction of caution — it is
 * a reason NOT to compare magnitudes, and a reason a zero Stock-in-Hand is treated as a real
 * configuration rather than corruption.)
 *
 * ## The three states, and why each lands where it does
 *
 * - `dr_negative`: both readings material, both negative. The stock idiom behaves like the
 *   verified group idiom; the card layer's flip is correct as written.
 * - `positive_magnitude`: stock Σ material and positive against a material, structurally-signed
 *   (negative) Stock-in-Hand. `$$IsDebit` is not firing for StockGroup on this Tally, and the
 *   extraction must negate — see the quirk consumer in the Bridge's cycle.
 * - `unknown`: everything else, and it is a third state because "could not tell" and "verified
 *   ok" are opposite instructions (see `debtorsHaveBalance` in flavour.ts). Specifically:
 *     - Stock Σ below evidence: a service business, or empty books. VACUOUS, not verified —
 *       the card shows ~0 under either hypothesis, so nothing is at risk today, but the moment
 *       inventory appears the question is live again. `shouldReprobe` re-asks daily rather than
 *       monthly while this state holds.
 *     - Stock Σ material but no material Stock-in-Hand to judge it against: a non-integrated
 *       book whose closing stock was never journalized, or a renamed reserved group. There is
 *       no trusted reference, and ONE unverifiable signal must not flip an extraction (the same
 *       discipline signs.ts applies: a single disagreeing group is a book anomaly, not a
 *       conviction). The extraction keeps the documented idiom, the quirk records that this is
 *       an ASSUMPTION, and support can see it the day a ticket says stock looks negative.
 *     - Stock-in-Hand material but POSITIVE (a credit balance on held stock): the reference
 *       violates its own structural sign, so it is suspect and not allowed to adjudicate —
 *       agreeing with a broken reference is not verification.
 *
 * ## Why `positive_magnitude` corrects rather than refuses
 *
 * The group canary REFUSES on 'inverted' because its failure mode is collapse — the Dr/Cr
 * distinction is destroyed row by row and no global transform recovers it, and every number in
 * the product is wrong. Here the situation is the opposite on both axes: the defect touches one
 * card, and the probe has MEASURED the correct global transform (a single negation). Refusing
 * to sync a whole company over a correctable, measured, single-card dialect difference gives
 * the owner an outage they can do nothing about; negating gives them a correct dashboard.
 * Measured knowledge is applied; only guesses are refused.
 *
 * This file reads SIGNS, not money. `Number(...)` here mirrors the canary in signs.ts — it is
 * evidence gathering, tolerant of malformed rows, and nothing it computes is ever published.
 */

export type StockSignVerdict = 'dr_negative' | 'positive_magnitude' | 'unknown';

export interface StockSignCheck {
  verdict: StockSignVerdict;
  /** Σ of the StockGroup rows' values AS SERVED BY THE DOUBTFUL IDIOM, in rupees. Sign evidence. */
  stockSum: number;
  /** Stock-in-Hand's closing under the verified group idiom; `undefined` = no such group row. */
  stockInHand: number | undefined;
}

/** Below a rupee, rounding and empty books are the likelier explanation than a signal. */
const MIN_EVIDENCE_RUPEES = 1;

/**
 * Decide the stock idiom's sign behaviour from one StockGroup response and the group oracle's
 * Stock-in-Hand reading.
 *
 * `stockRows` are positional rows in the `stockRequest` schema (F01 name, F02 closing value);
 * `valueIndex` exists so a schema change there fails a test here rather than silently reading
 * names as numbers. Malformed values are simply not evidence.
 */
export function checkStockSignConvention(
  stockRows: ReadonlyArray<readonly string[]>,
  stockInHandClosing: number | undefined,
  opts: { valueIndex?: number } = {},
): StockSignCheck {
  const valueIndex = opts.valueIndex ?? 1;

  // Float summation is fine for a signum with a whole-rupee evidence floor. Note this sums the
  // rows exactly as `stockCard` totals them, so the sign judged here is the sign of the very
  // number the product would display.
  let stockSum = 0;
  for (const row of stockRows) {
    const n = Number((row[valueIndex] ?? '').trim());
    if (Number.isFinite(n)) stockSum += n;
  }

  const sih =
    stockInHandClosing !== undefined && Number.isFinite(stockInHandClosing)
      ? stockInHandClosing
      : undefined;
  const base = { stockSum, stockInHand: sih };

  // Vacuous: with no material inventory value, both hypotheses produce the same (~zero) card.
  if (Math.abs(stockSum) < MIN_EVIDENCE_RUPEES) return { verdict: 'unknown', ...base };

  // No trusted reference: a non-integrated book, an unjournalized closing stock, or a renamed
  // reserved group. One unverifiable signal must not flip an extraction.
  if (sih === undefined || Math.abs(sih) < MIN_EVIDENCE_RUPEES) {
    return { verdict: 'unknown', ...base };
  }

  // A CREDIT balance on held stock violates the reference's structural sign. A suspect
  // reference adjudicates nothing — agreeing with it would be "verification" by a broken ruler.
  if (sih > 0) return { verdict: 'unknown', ...base };

  // The reference is material and carries its structural Dr-negative sign. Same sign means the
  // stock idiom resolved Dr/Cr like the verified group idiom; opposite means it handed us a
  // positive magnitude and the extraction must negate.
  return { verdict: stockSum < 0 ? 'dr_negative' : 'positive_magnitude', ...base };
}

const rupees = (n: number) => n.toFixed(2);

/** Support-facing, and safe to log: no customer data, only reserved names and totals of signs. */
export function describeStockSignCheck(check: StockSignCheck): string {
  const sihText =
    check.stockInHand === undefined ? 'absent' : `${rupees(check.stockInHand)}`;
  switch (check.verdict) {
    case 'dr_negative':
      return (
        `Stock $ClosingValue arrives Dr-negative like the verified group idiom ` +
        `(stock Σ ${rupees(check.stockSum)} vs Stock-in-Hand ${sihText}); the display flip is correct.`
      );
    case 'positive_magnitude':
      return (
        `Stock $ClosingValue arrives as a POSITIVE magnitude — $$IsDebit does not resolve Dr for ` +
        `StockGroup on this Tally (stock Σ ${rupees(check.stockSum)} against Stock-in-Hand ` +
        `${sihText}). The extraction negates stock values to restore Dr-negative.`
      );
    case 'unknown':
      if (Math.abs(check.stockSum) < MIN_EVIDENCE_RUPEES) {
        return check.stockInHand !== undefined && Math.abs(check.stockInHand) >= MIN_EVIDENCE_RUPEES
          ? `Stock sign not determinable: the books carry closing stock (${sihText}) but the ` +
              `inventory module values ~0 — an accounts-only book. Nothing is at risk while the ` +
              `stock card is empty; re-probing daily until stock items appear.`
          : `Stock sign not determinable: no material inventory value to judge (stock Σ ` +
              `${rupees(check.stockSum)}). Normal for a service business; re-probing daily until ` +
              `stock appears.`;
      }
      if (check.stockInHand === undefined || Math.abs(check.stockInHand) < MIN_EVIDENCE_RUPEES) {
        return (
          `Stock sign NOT verified: stock Σ ${rupees(check.stockSum)} is material but there is no ` +
          `material Stock-in-Hand balance to cross-check it against (non-integrated books, or ` +
          `closing stock never journalized). The documented Dr-negative idiom is ASSUMED — if a ` +
          `ticket says stock renders negative, this is where to look.`
        );
      }
      return (
        `Stock sign not determinable: Stock-in-Hand came back ${sihText}, a CREDIT balance on ` +
        `held stock, which violates its structural sign — the reference is suspect and was not ` +
        `allowed to adjudicate (stock Σ ${rupees(check.stockSum)}).`
      );
  }
}
