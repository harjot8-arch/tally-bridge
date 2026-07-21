import type {
  AgeingBucketRow,
  AgeingTotalRow,
  CashBankBalance,
  Company,
  GroupBalance,
  IsoDate,
  PeriodRevenueRow,
  Section,
  StockValueRow,
} from '@tally-bridge/core';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  dutiesTaxesCard,
  profitCard,
  salesTrendCard,
  stockCard,
  type AgeingCard,
  type CashBankCard,
  type DutiesTaxesCard,
  type ProfitCard,
  type StockCard,
  type TreeNode,
  type TrendCard,
} from '@tally-bridge/viewmodel';

/**
 * Decrypted section payloads → per-company card view models.
 *
 * This mirrors the desktop reader's assembly (apps/bridge/src/main/reader.ts,
 * `buildCompanyCards`) rather than importing it: apps/bridge is an Electron app, not a
 * publishable package, and its reader is welded to Electron IPC types and the local snapshot
 * store. The seam ARCHITECTURE.md defines for surfaces is `packages/viewmodel`, which BOTH
 * copies consume verbatim — all arithmetic lives there, so the two surfaces cannot disagree
 * about a number; what is duplicated here is only the "which section feeds which card" wiring.
 * If a third surface ever appears, this ~100 lines is the piece to hoist into viewmodel.
 *
 * FAILURE SHAPE, same rule as the desktop: one bad section must not blank six good cards, and
 * nothing here throws to the renderer. Every card builds inside its own catch; a failure marks
 * the company `failed` and the card is OMITTED — never rendered from coerced data (`paiseOf`
 * throws on wire values it does not understand, by design; softening that here would repeat the
 * exact bug it exists to stop).
 */

export interface CompanyCards {
  companyGuid: string;
  name: string;
  asOf: IsoDate;
  cashBank?: CashBankCard | undefined;
  dutiesTaxes?: DutiesTaxesCard | undefined;
  receivables?: AgeingCard | undefined;
  payables?: AgeingCard | undefined;
  profit?: ProfitCard | undefined;
  stock?: StockCard | undefined;
  salesTrend?: TrendCard | undefined;
  balanceSheet?: TreeNode[] | undefined;
}

export interface CompanySections {
  companyGuid: string;
  asOf: IsoDate;
  sections: ReadonlyMap<Section, unknown>;
}

function rowsOf<T>(payload: unknown): readonly T[] {
  const rows = (payload as { rows?: unknown }).rows;
  if (!Array.isArray(rows)) throw new Error('section payload has no rows array');
  return rows as T[];
}

function totalsOf<T>(payload: unknown): readonly T[] {
  const totals = (payload as { totals?: unknown }).totals;
  if (!Array.isArray(totals)) throw new Error('ageing payload has no totals array');
  return totals as T[];
}

export function assembleCompanyCards(
  acc: CompanySections,
  log: (message: string) => void,
): { cards: CompanyCards; failed: boolean } {
  let failed = false;

  const tryCard = <T>(name: string, fn: () => T): T | undefined => {
    try {
      return fn();
    } catch (e) {
      failed = true;
      log(`[web] ${name} card failed for ${acc.companyGuid}: ${(e as Error).message}`);
      return undefined;
    }
  };

  const companyRows = acc.sections.has('company')
    ? tryCard('company', () => rowsOf<Company>(acc.sections.get('company')))
    : undefined;
  const name = companyRows?.[0]?.name;

  const cards: CompanyCards = {
    companyGuid: acc.companyGuid,
    // The GUID is a poor label but an honest one (same choice as the desktop reader).
    name: typeof name === 'string' && name.length > 0 ? name : acc.companyGuid,
    asOf: acc.asOf,
  };

  if (acc.sections.has('cash_bank')) {
    cards.cashBank = tryCard('cash_bank', () =>
      cashBankCard(rowsOf<CashBankBalance>(acc.sections.get('cash_bank'))),
    );
  }
  if (acc.sections.has('duties_taxes')) {
    cards.dutiesTaxes = tryCard('dutiesTaxes', () =>
      dutiesTaxesCard(rowsOf<CashBankBalance>(acc.sections.get('duties_taxes'))),
    );
  }
  if (acc.sections.has('ageing_receivable')) {
    const p = acc.sections.get('ageing_receivable');
    cards.receivables = tryCard('receivables', () =>
      ageingCard(totalsOf<AgeingTotalRow>(p), rowsOf<AgeingBucketRow>(p), 'receivable'),
    );
  }
  if (acc.sections.has('ageing_payable')) {
    const p = acc.sections.get('ageing_payable');
    cards.payables = tryCard('payables', () =>
      ageingCard(totalsOf<AgeingTotalRow>(p), rowsOf<AgeingBucketRow>(p), 'payable'),
    );
  }
  if (acc.sections.has('stock_value')) {
    cards.stock = tryCard('stock', () =>
      stockCard(rowsOf<StockValueRow>(acc.sections.get('stock_value'))),
    );
  }
  if (acc.sections.has('period_revenue')) {
    const p = acc.sections.get('period_revenue');
    cards.profit = tryCard('profit', () => {
      const rows = rowsOf<PeriodRevenueRow>(p);
      const { current, previous } = splitPeriods(rows);
      return profitCard(current, previous);
    });
    cards.salesTrend = tryCard('salesTrend', () => salesTrendCard(rowsOf<PeriodRevenueRow>(p)));
  }
  if (acc.sections.has('group_balance')) {
    // `balanceSheetTree` filters revenue rows itself; profit/salesTrend deliberately come from
    // `period_revenue` instead — two projections of one idea, not merged (ARCHITECTURE.md).
    cards.balanceSheet = tryCard('balanceSheet', () =>
      balanceSheetTree(rowsOf<GroupBalance>(acc.sections.get('group_balance'))),
    );
  }

  return { cards, failed };
}

/**
 * Latest period vs the one before. Same split as the desktop reader: the steady-state payload
 * often holds only the current month, so `previous` being empty renders as a ₹0 baseline —
 * honest for an install with no history yet.
 */
function splitPeriods(rows: readonly PeriodRevenueRow[]): {
  current: PeriodRevenueRow[];
  previous: PeriodRevenueRow[];
} {
  const periods = [...new Set(rows.map((r) => r.period))].sort();
  const cur = periods.at(-1);
  const prev = periods.at(-2);
  return {
    current: cur === undefined ? [] : rows.filter((r) => r.period === cur),
    previous: prev === undefined ? [] : rows.filter((r) => r.period === prev),
  };
}
