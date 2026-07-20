/**
 * The sign-convention canary.
 *
 * ## The unverifiable it guards
 *
 * `expr.amount` is `if $$IsDebit:X then -$$NumValue:X else $$NumValue:X`, and the whole codebase
 * downstream — core's `Amount`, the P&L that falls out as a plain sum, every card — is built on
 * the convention that produces: **Dr negative, Cr positive**. That idiom is coherent ONLY IF
 * `$$NumValue` returns a MAGNITUDE. Only a real Tally closes that, and this file does not
 * pretend to. What it does is refuse to let the failure be silent.
 *
 * ## What the failure actually looks like — NOT what you would guess
 *
 * The natural assumption is "if `$$NumValue` is signed, every number inverts". **It does not**,
 * and getting this wrong makes the canary miss the very thing it is for. The expression negates
 * on the DEBIT BRANCH ONLY, so a signed `$$NumValue` corrupts exactly one side of the book:
 *
 *   H0  magnitude (assumed)      Dr -> -|x|  Cr -> +|x|    correct
 *   H1  signed, internal Dr=+    Dr -> -x    Cr -> -x      every group NEGATIVE: credits wrong
 *   H2  signed, internal Dr=-    Dr -> +x    Cr -> +x      every group POSITIVE: debits wrong
 *
 * So the signature is not inversion. It is COLLAPSE: every group in the book ends up sharing one
 * sign. That is impossible in a real book, where assets are debits and revenue is credit, and it
 * is what this file looks for.
 *
 * The argument previously used to dismiss all of this — "the reference implementation ships a
 * trailing `(-)` -> `-` rewrite that would be DEAD CODE if `$$NumValue` were already signed" —
 * is only half sound. It rules out H2, where nothing is ever negative and the rewrite really
 * would be dead. It says NOTHING about H1, where both branches go negative and the rewrite is
 * fully live. H1 is Tally's usual internal convention, so the argument leaves the likelier
 * hypothesis standing.
 *
 * ## Why this is sound where the balance check is not
 *
 * The tempting invariant is `Σ closing ≈ 0` — the chart of accounts balances. It is worthless
 * here: it is INVARIANT UNDER A GLOBAL SIGN FLIP, and under H1/H2 it does not even hold, but it
 * cannot say WHICH side broke. A known-sign invariant can.
 *
 * ## Why it is deliberately hard to fire
 *
 * A false positive refuses to sync a working install. A real book DOES contain a wrong-signed
 * group now and then — a credit cash balance is an ordinary data-entry error. So the bar is not
 * "something disagrees", it is **the disagreement partitions cleanly along the Dr/Cr axis**:
 * every debit-normal group wrong and every credit-normal group right, or vice versa, with at
 * least two independent signals in the wrong class. A book problem dissents WITHIN a class; an
 * arithmetic problem takes out a whole class at once. That distinction is the whole design.
 *
 * Only groups whose sign is structural are used. Sundry Debtors is excluded despite being the
 * obvious candidate: a party sitting on a large advance can genuinely flip it. Capital Account
 * is excluded: accumulated losses can exceed capital. Bank Accounts is excluded: overdrafts are
 * ordinary. Those are opinions about a business, not about arithmetic.
 */

export type SignVerdict = 'ok' | 'inverted' | 'unknown';

export interface SignCheck {
  verdict: SignVerdict;
  /** Groups whose sign matches "Dr negative, Cr positive". */
  agreed: string[];
  /** Groups whose sign is exactly backwards. */
  disagreed: string[];
}

/**
 * Reserved Tally groups whose normal balance is not a matter of opinion.
 *
 * Matched on the group's own name, exactly. A book that renamed a reserved group simply yields
 * no signal from it, which lands on `unknown` — silence, not a false accusation.
 */
const KNOWN_SIGNS: ReadonlyArray<{ re: RegExp; label: string; normal: 'debit' | 'credit' }> = [
  // A cash box cannot be overdrawn.
  { re: /^cash-in-hand$/i, label: 'Cash-in-Hand', normal: 'debit' },
  // Stock you hold is an asset; negative stock value is not a thing.
  { re: /^stock-in-hand$/i, label: 'Stock-in-Hand', normal: 'debit' },
  { re: /^fixed assets$/i, label: 'Fixed Assets', normal: 'debit' },
  { re: /^purchase accounts$/i, label: 'Purchase Accounts', normal: 'debit' },
  { re: /^direct expenses$/i, label: 'Direct Expenses', normal: 'debit' },
  { re: /^indirect expenses$/i, label: 'Indirect Expenses', normal: 'debit' },
  // The credit-normal side. There must be MORE THAN ONE of these or H1 — the hypothesis the
  // "dead code" argument fails to rule out — cannot clear the two-signal bar and would slip
  // through as `unknown`. A book whose net sales are a debit is a returns-only book; a book
  // where sales AND both income groups are all debits is not a book.
  { re: /^sales accounts$/i, label: 'Sales Accounts', normal: 'credit' },
  { re: /^direct incomes?$/i, label: 'Direct Income', normal: 'credit' },
  { re: /^indirect incomes?$/i, label: 'Indirect Income', normal: 'credit' },
];

/** Below a rupee, rounding and empty books are the likelier explanation than a signal. */
const MIN_EVIDENCE_RUPEES = 1;

/**
 * Read a group response for evidence that our Dr/Cr assumption is backwards.
 *
 * Indices default to the `groupsRequest` schema (F01 name, F06 closing). Parsing is deliberately
 * tolerant — this is a canary, not an extractor, and it must never be the thing that throws.
 */
export function checkGroupSignConvention(
  rows: ReadonlyArray<readonly string[]>,
  opts: { nameIndex?: number; closingIndex?: number } = {},
): SignCheck {
  const nameIndex = opts.nameIndex ?? 0;
  const closingIndex = opts.closingIndex ?? 5;

  const signals: Array<{ label: string; normal: 'debit' | 'credit'; agrees: boolean }> = [];

  for (const known of KNOWN_SIGNS) {
    const row = rows.find((r) => known.re.test((r[nameIndex] ?? '').trim()));
    if (!row) continue;

    const value = Number((row[closingIndex] ?? '').trim());
    if (!Number.isFinite(value) || Math.abs(value) < MIN_EVIDENCE_RUPEES) continue;

    // Dr negative, Cr positive.
    const expected = known.normal === 'debit' ? -1 : 1;
    signals.push({ label: known.label, normal: known.normal, agrees: Math.sign(value) === expected });
  }

  const agreed = signals.filter((s) => s.agrees).map((s) => s.label);
  const disagreed = signals.filter((s) => !s.agrees).map((s) => s.label);

  const debits = signals.filter((s) => s.normal === 'debit');
  const credits = signals.filter((s) => s.normal === 'credit');
  const allAgree = (xs: typeof signals) => xs.length > 0 && xs.every((s) => s.agrees);
  const allDisagree = (xs: typeof signals) => xs.length > 0 && xs.every((s) => !s.agrees);

  let verdict: SignVerdict = 'unknown';
  if (signals.length > 0 && signals.every((s) => s.agrees)) {
    verdict = 'ok';
  } else if (signals.length >= 2 && signals.every((s) => !s.agrees)) {
    // Nothing in the book has the sign it must have. Whatever the cause, do not publish it.
    verdict = 'inverted';
  } else if (debits.length >= 2 && allDisagree(debits) && allAgree(credits)) {
    verdict = 'inverted'; // H2: every debit came back positive.
  } else if (credits.length >= 2 && allDisagree(credits) && allAgree(debits)) {
    verdict = 'inverted'; // H1: every credit came back negative.
  }

  return { verdict, agreed, disagreed };
}

/** Support-facing, and safe to log: group names are reserved Tally names, never customer data. */
export function describeSignCheck(check: SignCheck): string {
  switch (check.verdict) {
    case 'ok':
      return `Amount signs agree with Dr-negative/Cr-positive (${check.agreed.join(', ')}).`;
    case 'inverted':
      return (
        `Amount signs are WRONG: ${check.disagreed.join(', ')} came back with the opposite sign ` +
        'to the one a real book must have' +
        (check.agreed.length > 0 ? ` (while ${check.agreed.join(', ')} came back right)` : '') +
        '. That pattern means $$NumValue returns a SIGNED value rather than a magnitude, so ' +
        "expr.amount's debit-branch negation collapses the book onto one sign instead of " +
        'resolving Dr/Cr. Every amount downstream is affected.'
      );
    case 'unknown':
      return (
        'Could not tell whether amount signs are right: ' +
        (check.agreed.length === 0 && check.disagreed.length === 0
          ? 'no reserved group carried a balance big enough to judge.'
          : `evidence conflicts (agree: ${check.agreed.join(', ') || 'none'}; ` +
            `disagree: ${check.disagreed.join(', ') || 'none'}).`)
      );
  }
}
