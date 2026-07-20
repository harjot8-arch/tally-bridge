import type { Section } from '@tally-bridge/core';

/**
 * The AlterID gate.
 *
 * AlterID is a per-company counter Tally bumps whenever a master or voucher changes. The
 * obvious use is as a DELTA CURSOR — "give me everything with AlterID > N". We deliberately do
 * not use it that way, for a verified reason: **AlterID cannot detect deletions.** A deleted
 * voucher does not bump anything observable; it just vanishes. Implementations that use AlterID
 * as a cursor have to pull every GUID+AlterID pair and set-diff client-side to compensate.
 *
 * We are immune to that, and the immunity is worth naming: the deletion problem only exists if
 * you sync rows that can be individually deleted. We sync AGGREGATES, and aggregates are
 * self-healing — delete a voucher and the group closing balance simply differs on the next
 * pull. So AlterID is used as a DIRTY BIT, not a cursor.
 *
 * The payoff: for an idle company at 15-minute polling, a cycle costs one ~2KB round trip and
 * nothing else. Tally is a single-threaded desktop app the owner is actively typing into; that
 * restraint is the entire point.
 */

export interface Watermark {
  companyGuid: string;
  /** Tally `$AltMstId` — the masters high-water mark. */
  altMstId: number;
  /** Tally `$AltVchId` — the vouchers high-water mark. */
  altVchId: number;
}

export type GateDecision =
  /** Nothing changed. Zero further requests, zero upload. The common case. */
  | { action: 'skip'; reason: string }
  /** Pull only the sections implied by what moved. */
  | { action: 'partial'; sections: Section[]; reason: string }
  /** Watermarks are void; pull everything and reset. */
  | { action: 'full'; reason: string };

/** Sections that must be re-pulled when vouchers move. */
const VOUCHER_SECTIONS: Section[] = [
  'group_balance',
  'cash_bank',
  'ageing_receivable',
  'ageing_payable',
  'stock_value',
  'period_revenue',
];

/**
 * Sections that must be re-pulled when masters move.
 *
 * Masters are the chart of accounts, ledgers, and stock groups. A master edit can rename or
 * re-parent a group without touching a single voucher, which changes what the cards say without
 * changing any number.
 */
const MASTER_SECTIONS: Section[] = ['company', 'group_balance', 'cash_bank', 'stock_value'];

/**
 * An AlterID we are willing to reason about.
 *
 * This exists because of HOW the comparisons below fail. `NaN < x` and `NaN > x` are BOTH
 * false, so a single garbled probe column (an empty `<ALTMSTID/>`, a parser that gave up)
 * makes both the backward check and the moved checks miss, and the gate falls through to
 * "watermarks unchanged" — SKIP. Not once: every cycle, forever, silently, while the owner
 * watches a frozen dashboard. The unsafe direction is the one NaN happens to take.
 *
 * So garbage must fail SAFE (pull everything, correct-but-slow), never fail QUIET.
 */
function usable(n: number): boolean {
  return Number.isFinite(n) && n >= 0;
}

export function decideGate(
  stored: Watermark | undefined,
  current: Watermark,
): GateDecision {
  // First sight of this company.
  if (!stored) {
    return { action: 'full', reason: 'no stored watermark for this company' };
  }

  // Before any comparison, not after: a watermark we cannot compare is a watermark we do not
  // have. Callers may sanitise upstream, but this function is exported and the property it
  // guards — the owner is never shown a stale number under a green checkmark — cannot depend
  // on every present and future caller remembering to.
  if (!usable(current.altMstId) || !usable(current.altVchId)) {
    return { action: 'full', reason: 'current AlterID is not a usable number; watermarks are void' };
  }
  if (!usable(stored.altMstId) || !usable(stored.altVchId)) {
    return { action: 'full', reason: 'stored AlterID is not a usable number; watermarks are void' };
  }

  // Company GUID is the identity, always. Names get edited ("ABC Traders" -> "ABC Traders Pvt
  // Ltd") and are duplicated across financial years, so keying on name silently merges or
  // splits financial history — corruption that only surfaces months later.
  if (stored.companyGuid !== current.companyGuid) {
    return { action: 'full', reason: 'company GUID changed; never merge across GUIDs' };
  }

  // THE SUBTLE ONE. Restoring from a backup, or a Tally data rewrite, can leave AlterID LOWER
  // than what we stored. A naive `>` comparison would then conclude "nothing new" on every
  // subsequent cycle and skip syncing FOREVER, silently, while the owner watches a frozen
  // dashboard. Same GUID + lower AlterID is the signature.
  if (current.altMstId < stored.altMstId || current.altVchId < stored.altVchId) {
    return {
      action: 'full',
      reason: 'AlterID moved backward (restore from backup or data rewrite); watermarks are void',
    };
  }

  const mastersMoved = current.altMstId > stored.altMstId;
  const vouchersMoved = current.altVchId > stored.altVchId;

  if (!mastersMoved && !vouchersMoved) {
    return { action: 'skip', reason: 'watermarks unchanged' };
  }

  if (mastersMoved && vouchersMoved) {
    return { action: 'full', reason: 'both masters and vouchers changed' };
  }

  const sections = vouchersMoved ? VOUCHER_SECTIONS : MASTER_SECTIONS;
  return {
    action: 'partial',
    sections: [...sections],
    reason: vouchersMoved ? 'vouchers changed' : 'masters changed',
  };
}

/**
 * The second gate, in series with the first.
 *
 * AlterID says "don't even ASK Tally". Section hashing says "don't UPLOAD". They catch
 * different things: AlterID moves whenever ANY voucher changes, but a voucher change usually
 * leaves most sections identical — a sales entry moves the P&L and the debtors, and leaves the
 * stock summary exactly as it was.
 */
export function shouldUpload(
  storedHash: string | undefined,
  currentHash: string,
): boolean {
  return storedHash !== currentHash;
}

/**
 * Hash-hit rate: the health metric that catches a silently-defeated gate.
 *
 * If canonicalization is subtly non-deterministic — a key order that varies, a float that
 * formats differently, a `-0` — the hash flaps, every cycle uploads, and NOTHING ERRORS. You
 * simply pay for bandwidth forever and never find out. On an idle company this rate should sit
 * near 1.0; near 0 means the gate is broken, not that the business is busy.
 */
export function hashHitRate(stats: { checked: number; skipped: number }): number {
  if (stats.checked === 0) return 1;
  return stats.skipped / stats.checked;
}
