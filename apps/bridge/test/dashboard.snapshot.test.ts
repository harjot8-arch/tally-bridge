import { test } from 'node:test';
import assert from 'node:assert/strict';
import type {
  AgeingBucketRow,
  AgeingTotalRow,
  CashBankBalance,
  GroupBalance,
  PeriodRevenueRow,
} from '@tally-bridge/core';
import { ageingCard, balanceSheetTree, cashBankCard, profitCard, salesTrendCard } from '@tally-bridge/viewmodel';
import type { BridgeApi, CompanyCards, GetCardsResult } from '../src/main/ipc.ts';
import type { SyncStatus } from '../src/main/scheduler.ts';
import { buildModel, hasNoCards } from '../src/renderer/snapshot.ts';
import { mountDashboard } from '../src/renderer/dashboard.ts';
import { allText, byClass, firstByClass, installDom, type FakeNode } from './dashboard.dom.ts';

/**
 * The wire -> the screen.
 *
 * `getCards()` resolves to a `GetCardsResult`: a discriminated union of four states, whose
 * `ready` variant carries cards the MAIN process already built with `@tally-bridge/viewmodel`.
 * So these tests build their fixtures by running the real card layer over real wire rows —
 * nothing between the 2dp strings and the nodes is stubbed, because that seam is where the bugs
 * worth catching live.
 *
 * The mount tests cover the half that has no happy version: what the owner sees when IPC
 * REJECTS, when the data is locked, and when the numbers on screen are stale.
 */

const dom = installDom();
process.on('exit', () => dom.uninstall());

const GUID_A = 'guid-acme';
const GUID_B = 'guid-beta';
const HOSTILE = 'A & B Traders <Mumbai>';

// Cash is an ASSET: Dr, and Dr is negative in the house convention, so a healthy bank balance
// arrives with a minus sign and the card layer flips it.
const cashRow = (ledgerName: string, closing: string): CashBankBalance => ({
  companyGuid: GUID_A,
  asOf: '2026-07-16',
  ledgerName,
  parent: 'Bank Accounts',
  closing,
});

const arTotal: AgeingTotalRow = {
  companyGuid: GUID_A,
  asOf: '2026-07-16',
  side: 'receivable',
  bucket: '0_30',
  amount: '-100000.00',
  billCount: 1,
};

const arRow: AgeingBucketRow = {
  companyGuid: GUID_A,
  asOf: '2026-07-16',
  side: 'receivable',
  partyName: HOSTILE,
  bucket: '0_30',
  amount: '-100000.00',
  billCount: 1,
};

const revRows: PeriodRevenueRow[] = [
  { companyGuid: GUID_A, period: '2026-06', groupName: 'Sales', parent: '', amount: '400000.00' },
  { companyGuid: GUID_A, period: '2026-07', groupName: 'Sales', parent: '', amount: '500000.00' },
];

/** One company's cards, exactly as the main process assembles them. */
function acme(overrides: Partial<CompanyCards> = {}): CompanyCards {
  return {
    companyGuid: GUID_A,
    name: 'Acme Traders',
    asOf: '2026-07-16',
    cashBank: cashBankCard([cashRow('HDFC CA 4471', '-342110.00')]),
    receivables: ageingCard([arTotal], [arRow], 'receivable'),
    profit: profitCard([revRows[1]!], [revRows[0]!]),
    salesTrend: salesTrendCard(revRows),
    ...overrides,
  };
}

function beta(): CompanyCards {
  return {
    companyGuid: GUID_B,
    name: `Beta ${HOSTILE}`,
    asOf: '2026-07-15',
    cashBank: cashBankCard([{ ...cashRow('ICICI', '-900000.00'), companyGuid: GUID_B }]),
  };
}

const ready = (companies: CompanyCards[], incomplete = false): GetCardsResult => ({
  state: 'ready',
  companies,
  incomplete,
});

// ---------------------------------------------------------------- the four states

test('READY: the selected company\'s cards come through untouched', () => {
  const m = buildModel(ready([acme()]));
  assert.equal(m.state, 'ready');
  assert.equal(m.cards?.cashBank?.total.display, '₹3,42,110');
  assert.equal(m.cards?.receivables?.topParties[0]?.name, HOSTILE);
  assert.equal(m.selected, GUID_A);
  assert.equal(m.incomplete, false);
});

test('LOCKED carries a problem sentence only when there is one', () => {
  const plain = buildModel({ state: 'locked' });
  assert.equal(plain.state, 'locked');
  assert.equal(plain.message, undefined, 'a wrong passphrase must never leave a message here');

  const withProblem = buildModel({ state: 'locked', problem: 'Your stored key is out of date.' });
  assert.equal(withProblem.message, 'Your stored key is out of date.');
});

test('EMPTY and ERROR pass through as themselves', () => {
  assert.equal(buildModel({ state: 'empty' }).state, 'empty');
  const e = buildModel({ state: 'error', message: 'Your data could not be read.' });
  assert.equal(e.state, 'error');
  assert.equal(e.message, 'Your data could not be read.');
});

test('A REJECTED CALL IS NOT AN EMPTY COMPANY', () => {
  // `null` is what `ask()` returns when the IPC call itself rejected. "Nothing has synced yet"
  // and "the Bridge is not answering" are different sentences with different actions, and
  // showing the first when the second is true is the quiet lie this dashboard exists to avoid.
  assert.equal(buildModel(null).state, 'unavailable');
  assert.equal(buildModel(undefined).state, 'unavailable');
});

test('ready with zero companies is empty, not a switcher over nothing', () => {
  assert.equal(buildModel(ready([])).state, 'empty');
});

test('an unknown state from the wire degrades to unavailable rather than throwing', () => {
  // This value crossed a process boundary: "the type says it cannot happen" is a claim about
  // our source, not about the bytes that arrived.
  const m = buildModel({ state: 'something_new' } as unknown as GetCardsResult);
  assert.equal(m.state, 'unavailable');
});

test('a company with no cards at all is recognised as blank', () => {
  assert.equal(hasNoCards(undefined), true);
  assert.equal(hasNoCards({ companyGuid: GUID_A, name: 'New Co', asOf: '2026-07-16' }), true);
  assert.equal(hasNoCards(acme()), false);
});

// ---------------------------------------------------------------- company selection

test('the remembered company is honoured, and a vanished one falls back', () => {
  const both = ready([acme(), beta()]);
  assert.equal(buildModel(both).selected, GUID_A, 'the first by default');
  assert.equal(buildModel(both, GUID_B).selected, GUID_B);
  assert.equal(buildModel(both, GUID_B).cards?.cashBank?.total.display, '₹9,00,000');
  // The company was closed in Tally since the last paint.
  assert.equal(buildModel(ready([acme()]), GUID_B).selected, GUID_A);
});

test('a company with no name falls back to its GUID rather than rendering blank', () => {
  const m = buildModel(ready([{ ...acme(), name: '' }]));
  assert.equal(m.companies[0]?.name, GUID_A);
});

// ---------------------------------------------------------------- mounting

/**
 * A whole `BridgeApi`, because the type demands one.
 *
 * The dashboard uses four of these verbs. The rest exist here only to satisfy the interface, and
 * they THROW rather than returning a plausible value: if this file ever starts depending on the
 * wizard half of the bridge, that is a design mistake and it should fail loudly in a test rather
 * than quietly work against a stub. The onboarding wizard is another surface's problem.
 */
function fakeBridge(overrides: Partial<BridgeApi> = {}): BridgeApi {
  const notOurs = (verb: string) => (): never => {
    throw new Error(`the dashboard must not call ${verb}`);
  };
  return {
    getStatus: async () => ({ state: 'ok', message: 'Synced', lastRun: 1_000_000 }) as SyncStatus,
    syncNow: async () => {},
    isProvisioned: async () => true,
    detectTally: async () => ({ reachable: true, message: '', companies: [] }),
    unlock: async () => true,
    lock: async () => {},
    getCards: async () => ready([acme()]),
    openExternal: async () => {},
    onStatusChanged: () => () => {},
    getWizardState: notOurs('getWizardState'),
    sendWizardEvent: notOurs('sendWizardEvent'),
    onWizardStateChanged: notOurs('onWizardStateChanged'),
    recoveryQr: notOurs('recoveryQr'),
    printRecoverySheet: notOurs('printRecoverySheet'),
    ...overrides,
  };
}

const container = (): FakeNode => document.createElement('div') as unknown as FakeNode;

/** Let the refresh chain behind a click settle. */
const settle = async (): Promise<void> => {
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
};

test('mountDashboard paints the cards, the sync line and the as-of date', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge(),
    now: () => 1_000_000 + 120_000,
  });
  await dash.refresh();

  assert.ok(allText(root).includes('Synced 2 min ago'), allText(root));
  assert.ok(allText(root).includes('₹3,42,110'));
  assert.ok(allText(root).includes(HOSTILE), 'the hostile name reached the screen, as text');
  assert.ok(allText(root).includes('Figures as of 16 Jul 2026'));
  assert.equal(firstByClass(root, 'grid')?.classList.contains('stale'), false);
  dash.destroy();
});

test('A REJECTING getCards SHOWS A SENTENCE, NOT A FROZEN SCREEN', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getCards: () => Promise.reject(new Error('EPIPE: main process is on fire')) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  const text = allText(root);
  assert.ok(!text.includes('EPIPE'), text);
  assert.ok(!text.includes('Error'), text);
  assert.ok(text.includes('not responding'), 'and it must not read as "no data yet"');
  assert.ok(!text.includes('No data yet'));
  assert.equal(firstByClass(root, 'skeleton'), undefined, 'the skeleton must not be left up forever');
  // One action, never a dead end.
  assert.ok(byClass(root, 'status-action').some((b) => b.textContent === 'Try again'));
  dash.destroy();
});

test('a rejecting getStatus still paints, and never claims to be synced', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getStatus: () => Promise.reject(new Error('gone')) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  assert.ok(!allText(root).includes('Synced'), 'a failed status must never read as synced');
  assert.equal(firstByClass(root, 'dot')?.className, 'dot error');
  dash.destroy();
});

test('THE "SYNCING…" BUTTON COMES BACK when syncNow rejects', async () => {
  // A `.finally()` here does NOT handle the rejection — it re-throws after running — and the
  // button read "Syncing…" for the rest of the session.
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ syncNow: () => Promise.reject(new Error('Tally closed mid-sync')) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  const btn = byClass(root, 'status-action').find((b) => b.className.includes('primary'))!;
  assert.equal(btn.textContent, 'Sync now');
  btn.click();
  await settle();

  const after = byClass(root, 'status-action').find((b) => b.className.includes('primary'))!;
  assert.equal(after.textContent, 'Sync now', 'the button must never be left reading "Syncing…"');
  assert.equal(after.disabled, false);
  dash.destroy();
});

test('STALE DATA IS NEVER SHOWN UNDER A GREEN CHECKMARK', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getStatus: async () =>
        ({ state: 'waiting', message: 'Waiting for Tally to open', action: 'Open Tally' }) as SyncStatus,
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  // Three independent signals, none of them the only one: the dot, the sentence, the numbers.
  assert.equal(firstByClass(root, 'dot')?.className, 'dot waiting');
  assert.ok(allText(root).includes('Waiting for Tally to open'));
  assert.ok(allText(root).includes('may have changed'), 'the staleness must be stated in words');
  assert.equal(firstByClass(root, 'grid')?.classList.contains('stale'), true);
  assert.ok(byClass(root, 'status-action').some((b) => b.textContent === 'Open Tally'));
  dash.destroy();
});

test('the locked state says so, and offers the shell\'s unlock when there is one', async () => {
  const root = container();
  let asked = 0;
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getCards: async () => ({ state: 'locked' }) }),
    now: () => 1_000_000,
    onUnlockRequested: () => asked++,
  });
  await dash.refresh();

  assert.ok(allText(root).includes('locked'));
  const btn = byClass(root, 'status-action').find((b) => b.textContent === 'Unlock')!;
  btn.click();
  assert.equal(asked, 1);
  dash.destroy();
});

test('locked with no unlock handler still says what is true, with no dead button', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getCards: async () => ({ state: 'locked', problem: 'Your stored key is out of date.' }) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  assert.ok(allText(root).includes('Your stored key is out of date.'));
  assert.equal(
    byClass(root, 'status-action').some((b) => b.textContent === 'Unlock'),
    false,
  );
  dash.destroy();
});

test('an incomplete payload says some figures are missing', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getCards: async () => ready([acme({ stock: undefined })], true) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  assert.ok(firstByClass(root, 'banner'), 'the owner must be told the picture is partial');
  assert.ok(allText(root).includes('Some figures are missing'));
  // The cards that DID arrive are untouched.
  assert.ok(allText(root).includes('₹3,42,110'));
  dash.destroy();
});

test('an absent card costs its slot and nothing else', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: async () => ready([acme({ receivables: undefined, salesTrend: undefined })]),
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  assert.ok(allText(root).includes('₹3,42,110'), 'cash still renders');
  assert.equal(byClass(root, 'donut-slice').length, 0);
  assert.ok(!allText(root).includes('undefined'), allText(root));
  dash.destroy();
});

test('a brand-new company with no cards gets one calm sentence, not a wall of empties', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: async () => ready([{ companyGuid: GUID_A, name: 'New Co', asOf: '2026-07-16' }]),
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  assert.ok(firstByClass(root, 'empty'));
  assert.equal(firstByClass(root, 'grid'), undefined);
  assert.ok(allText(root).includes('No data yet'));
  dash.destroy();
});

test('Tally being closed with nothing synced says THAT, not the generic line', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: async () => ({ state: 'empty' }),
      getStatus: async () =>
        ({ state: 'waiting', message: 'Waiting for Tally to open', action: 'Open Tally' }) as SyncStatus,
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  // Tally being shut on a Sunday is not an error, and the sentence should be the useful one.
  assert.ok(allText(root).includes('Waiting for Tally to open'));
  dash.destroy();
});

test('a status push retones the grid without rebuilding it', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, { bridge: fakeBridge(), now: () => 1_000_000 });
  await dash.refresh();

  const grid = firstByClass(root, 'grid')!;
  dash.setStatus({ state: 'error', message: 'Tally stopped responding.', action: 'Try again' });
  assert.equal(grid.classList.contains('stale'), true);
  assert.equal(firstByClass(root, 'grid'), grid, 'a repaint here would drop scroll position and open rows');
  dash.destroy();
});

test('switching language repaints in Hindi without re-fetching', async () => {
  let fetches = 0;
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: async () => {
        fetches++;
        return ready([acme()]);
      },
    }),
    now: () => 1_000_000,
    locale: 'en',
  });
  await dash.refresh();
  const before = fetches;

  dash.setLocale('hi');
  assert.ok(allText(root).includes('नकद और बैंक'));
  assert.ok(allText(root).includes(HOSTILE), 'a party name is never translated');
  assert.ok(allText(root).includes('₹3,42,110'), 'and the numbering is Indian in both languages');
  assert.equal(fetches, before, 'a language switch must not hit Tally');
  assert.equal(document.documentElement.getAttribute('lang'), 'hi');
  dash.destroy();
});

test('the company picker only appears when there is a choice, and switching is filtered', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({ getCards: async () => ready([acme(), beta()]) }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  const chips = byClass(root, 'company');
  assert.equal(chips.length, 2);
  assert.ok(allText(root).includes('₹3,42,110'));

  chips[1]!.click();
  await settle();
  assert.ok(allText(root).includes('₹9,00,000'));
  // The two companies are never added together — each card is one company's, by construction.
  assert.ok(!allText(root).includes('₹12,42,110'));
  // A company NAME is attacker-influenced text too.
  assert.ok(allText(root).includes(`Beta ${HOSTILE}`));
  dash.destroy();
});

test('one company draws no picker', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, { bridge: fakeBridge(), now: () => 1_000_000 });
  await dash.refresh();
  assert.equal(byClass(root, 'company').length, 0);
  dash.destroy();
});

test('destroy() unsubscribes, stops the clock, and cannot repaint afterwards', async () => {
  let unsubscribed = false;
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      onStatusChanged: () => () => {
        unsubscribed = true;
      },
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();
  dash.destroy();

  assert.equal(unsubscribed, true);
  assert.equal(root.childNodes.length, 0);
  await dash.refresh();
  assert.equal(root.childNodes.length, 0, 'a late refresh must not repaint a torn-down container');
});

test('a preload that refuses the subscription does not stop the dashboard mounting', async () => {
  // The preload caps status listeners at 8 and THROWS past it.
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      onStatusChanged: () => {
        throw new Error('too many status listeners');
      },
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();
  assert.ok(allText(root).includes('₹3,42,110'));
  dash.destroy();
});

// ---------------------------------------------------------------- the balance sheet

/**
 * The Balance Sheet mount.
 *
 * These exist because the card was WRITTEN AND TESTED for weeks and never appeared on screen.
 * `renderSheet` had unit tests (dashboard.cards.test.ts) and `balanceSheetTree` had unit tests,
 * and both were green the entire time, because neither knows whether anyone ever calls it.
 * `CompanyCards` had no `balanceSheet` field, so `paintContent` could not mount what it could
 * not receive — and the whole suite stayed green through a missing headline feature.
 *
 * So these tests assert the SEAM rather than the renderer: that a tree handed to the mount
 * reaches the screen, and that a company holding only a balance sheet is not called empty.
 *
 * Dr negative / Cr positive is the house convention, and `balanceSheetTree` deliberately flips
 * nothing — so these fixtures read the way Tally actually sends them.
 */
const sheetRows: GroupBalance[] = [
  { companyGuid: GUID_A, asOf: '2026-07-16', groupName: 'Current Assets', parent: '', primaryGroup: 'Current Assets', isRevenue: false, opening: '-100000.00', closing: '-542110.00' },
  { companyGuid: GUID_A, asOf: '2026-07-16', groupName: 'Bank Accounts', parent: 'Current Assets', primaryGroup: 'Current Assets', isRevenue: false, opening: '-100000.00', closing: '-342110.00' },
  { companyGuid: GUID_A, asOf: '2026-07-16', groupName: 'Sales', parent: '', primaryGroup: 'Sales Accounts', isRevenue: true, opening: '0.00', closing: '500000.00' },
];

test('THE BALANCE SHEET REACHES THE SCREEN: a tree in CompanyCards is painted', async () => {
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: () => Promise.resolve(ready([acme({ balanceSheet: balanceSheetTree(sheetRows) })])),
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  // The root group. If the mount is removed from paintContent, this is what goes red.
  assert.ok(allText(root).includes('Current Assets'), allText(root));
  // The other cards still painted — mounting the sheet must not cost a slot.
  assert.ok(allText(root).includes('₹3,42,110'));
  dash.destroy();
});

test('the P&L side never appears on the balance sheet', async () => {
  // A company with ONLY the sheet, deliberately: `acme()` carries a sales-trend card that draws
  // the word "Sales" itself, so a page-wide assertion here would be measuring the wrong card and
  // would fail for a reason that has nothing to do with the balance sheet. (It did, when I first
  // wrote it that way.) Isolating the company isolates the claim.
  //
  // The claim: `balanceSheetTree` filters `isRevenue` itself, and `sheetRows` includes a revenue
  // group precisely so that this can be observed rather than assumed. A revenue group reaching
  // the balance sheet is the double-count that keeping BS and P&L as separate projections of one
  // row set exists to prevent.
  const root = container();
  const dash = mountDashboard(root as unknown as Element, {
    bridge: fakeBridge({
      getCards: () =>
        Promise.resolve(
          ready([
            {
              companyGuid: GUID_A,
              name: 'Acme Traders',
              asOf: '2026-07-16',
              balanceSheet: balanceSheetTree(sheetRows),
            },
          ]),
        ),
    }),
    now: () => 1_000_000,
  });
  await dash.refresh();

  const text = allText(root);
  assert.ok(text.includes('Current Assets'), text);
  assert.ok(!text.includes('Sales'), `a revenue group reached the balance sheet: ${text}`);
  dash.destroy();
});

test('a company whose ONLY section is group_balance is NOT reported as empty', () => {
  // The bug this pins: `hasNoCards` enumerates the six glance cards by hand. Forget to add
  // `balanceSheet` to that list and a company holding a complete balance sheet is told
  // "nothing has synced yet" — a blank screen sitting on top of perfectly good data.
  const onlySheet: CompanyCards = {
    companyGuid: GUID_A,
    name: 'Acme Traders',
    asOf: '2026-07-16',
    balanceSheet: balanceSheetTree(sheetRows),
  };
  assert.equal(hasNoCards(onlySheet), false);
});

test('an EMPTY tree is not a card — a heading over nothing is worse than an honest blank', () => {
  // `balanceSheetTree([])` is `[]`, not undefined: a group_balance section that synced but held
  // no non-revenue rows. Presence is therefore not the right check anywhere; length is.
  const emptySheet: CompanyCards = {
    companyGuid: GUID_A,
    name: 'Acme Traders',
    asOf: '2026-07-16',
    balanceSheet: [],
  };
  assert.equal(hasNoCards(emptySheet), true, 'an empty tree must not count as a card');
});
