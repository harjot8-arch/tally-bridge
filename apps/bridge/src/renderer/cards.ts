import type {
  AgeingCard,
  CashBankCard,
  ProfitCard,
  StockCard,
  Tone,
  TreeNode,
  TrendCard,
} from '@tally-bridge/viewmodel';
// `formatMoney`, never `Intl.NumberFormat('en-IN')` — ARCHITECTURE pins this: Intl's grouping
// depends on the ICU data the runtime shipped with, and a runtime without full ICU silently
// falls back to en-US, printing `₹1,42,34,110` as `₹14,234,110`. That is the one thing this
// market must never see, and it fails silently rather than loudly.
import { formatMoney } from '@tally-bridge/viewmodel';
import { columnChart, donut, donutCenter, type Column, type Slice } from './charts.ts';
import { button, clear, el, mount, setVar } from './dom.ts';
import { monthLabel, type Locale, type StringKey, type T } from './i18n.ts';

/**
 * Card rendering.
 *
 * This file maps view models to pixels and does NOTHING else. It contains no money arithmetic,
 * no formatting and no business rules — those all live in `packages/viewmodel`, which is why a
 * future mobile surface can reuse them and why every surface agrees on every number.
 *
 * The two jobs that ARE this file's:
 *
 *   1. Mapping semantic tones to colour. The viewmodel says "bad"; this file says bad is red,
 *      by putting `bad` in a class name and letting styles.css decide. A native client decides
 *      differently and nothing breaks.
 *   2. Mapping semantic tokens to words. `b.bucket` is `'91_180'`; `i18n.ts` decides whether
 *      that reads "91–180 days" or "91–180 दिन".
 *
 * Every rupee string on screen is `MoneyValue.display` or `.compact`, produced once by the card
 * layer. Bar widths and arc lengths are computed from `.paise` — exact integers — and never
 * from `.raw`. Adding `raw` values is BUG-6, and BUG-6 shipped believable numbers.
 */

// ---------------------------------------------------------------- scaffolding

export type CardWidth = 'normal' | 'wide' | 'full';

function card(title: string, width: CardWidth = 'normal'): HTMLElement {
  const c = el('section', `card ${width}`);
  mount(c, el('h2', 'card-title', title));
  return c;
}

/** The tone dot that stands in for a colour key. Never colour alone — see the chips too. */
function dot(tone: Tone): HTMLElement {
  const d = el('span', `tone-dot ${tone}`);
  d.setAttribute('aria-hidden', 'true');
  return d;
}

function big(text: string, tone: Tone): HTMLElement {
  return el('div', `big ${tone}`, text);
}

/**
 * A bar whose width is a proportion of the biggest thing on the card.
 *
 * `share` is 0..1 and is always computed from integer paise by the caller. The minimum width is
 * 2% so that a real-but-tiny amount is still a visible mark rather than nothing — the row's
 * number is beside it, so the bar never has to carry precision.
 */
function bar(tone: Tone, share: number): HTMLElement {
  const track = el('div', 'bar-track');
  const fill = el('div', `bar-fill ${tone}`);
  setVar(fill, '--w', `${(Math.max(0.02, Math.min(1, share)) * 100).toFixed(2)}%`);
  mount(track, fill);
  return track;
}

/** One plain sentence, one action. Never a code, never a stack trace. */
export function renderEmpty(message: string, actionLabel?: string, onAction?: () => void): HTMLElement {
  const wrap = el('div', 'empty');
  mount(wrap, el('div', 'empty-text', message));
  if (actionLabel && onAction) mount(wrap, button('status-action', actionLabel, onAction));
  return wrap;
}

function emptyNote(text: string): HTMLElement {
  return el('div', 'card-empty', text);
}

// ---------------------------------------------------------------- cash & bank

/**
 * The first question of the morning: how much money do I have?
 *
 * NO SPARKLINE HERE, and that is a decision rather than an omission. The plan called for one,
 * but `CashBankBalance` (packages/core) is a CLOSING BALANCE as of one date — the wire format
 * carries no cash history at all, by design, because the alternative is pulling voucher lines
 * (see EXCLUDED_BY_DESIGN). A sparkline would therefore have to be invented from a single
 * point, and a fabricated trend line on the one number an owner acts on is the worst thing
 * this file could draw. What replaces it answers a question the data CAN answer: where the
 * money actually sits.
 */
export function renderCashBank(vm: CashBankCard, t: T): HTMLElement {
  const c = card(t('card.cash'));
  mount(c, big(vm.total.display, vm.tone));

  if (vm.accounts.length === 0) {
    mount(c, emptyNote(t('cash.empty')));
    return c;
  }

  mount(
    c,
    el(
      'div',
      'sub',
      vm.tone === 'bad'
        ? t('cash.overdrawn')
        : vm.accounts.length === 1
          ? t('cash.oneAccount')
          : t('cash.accounts', { n: vm.accounts.length }),
    ),
  );

  // Composition, in exact paise. Only drawn when every account is in credit and the total is
  // positive: one overdrawn account makes "share of the total" exceed 1 for the others, and a
  // stacked bar that overflows its own track is a picture of a number that does not exist.
  const positive = vm.accounts.every((a) => a.balance.paise >= 0) && vm.total.paise > 0;
  if (positive) {
    const stack = el('div', 'stack');
    stack.setAttribute('aria-hidden', 'true'); // the same split is listed as text below
    for (const a of vm.accounts) {
      if (a.balance.paise <= 0) continue;
      const seg = el('div', `stack-seg ${a.isCash ? 'cash' : 'bank'}`);
      setVar(seg, '--w', `${((a.balance.paise / vm.total.paise) * 100).toFixed(3)}%`);
      mount(stack, seg);
    }
    mount(c, stack);
  }

  mount(c, collapsibleRows(vm.accounts.map((a) => ledgerRow(a)), t));
  return c;
}

function ledgerRow(a: CashBankCard['accounts'][number]): HTMLElement {
  const row = el('div', 'row');
  const swatch = el('span', `swatch ${a.isCash ? 'cash' : 'bank'}`);
  swatch.setAttribute('aria-hidden', 'true');
  // a.name is a ledger name out of a customer's Tally file — attacker-influenceable text.
  // `el()` sets it through textContent; nothing on this path touches innerHTML.
  mount(row, swatch, el('span', 'row-name', a.name), el('span', 'row-value', a.balance.display));
  return row;
}

const ROW_LIMIT = 6;

/**
 * Show the first few rows and hide the tail behind a button.
 *
 * A company with 40 bank ledgers otherwise makes the cash card taller than the window and
 * pushes the receivables card — the reason the app exists — below the fold. The button is a
 * real `<button>`, so it is reachable by keyboard and announced.
 */
function collapsibleRows(rows: HTMLElement[], t: T): HTMLElement {
  const wrap = el('div', 'rows');
  if (rows.length <= ROW_LIMIT + 1) {
    mount(wrap, ...rows);
    return wrap;
  }

  let expanded = false;
  const list = el('div', 'rows');
  const toggle = button('link-button', t('action.showAll', { n: rows.length }), () => {
    expanded = !expanded;
    paint();
  });
  const paint = (): void => {
    clear(list);
    mount(list, ...(expanded ? rows : rows.slice(0, ROW_LIMIT)));
    toggle.textContent = expanded ? t('action.showLess') : t('action.showAll', { n: rows.length });
    toggle.setAttribute('aria-expanded', String(expanded));
  };
  paint();
  mount(wrap, list, toggle);
  return wrap;
}

// ---------------------------------------------------------------- ageing

/**
 * Receivables and payables.
 *
 * A donut AND bars, which is not indecision. They answer different questions and the owner asks
 * both in the same glance: the ring says "how much of what I am owed has gone bad" (a
 * proportion, which is what a ring is for), and the bars beside it say "how much, and how late"
 * (a magnitude comparison, which bars win and rings lose). Neither alone is the card.
 *
 * The ring is dropped, not faked, whenever the book is not a positive whole — see `donut()`.
 */
export function renderAgeing(vm: AgeingCard, t: T): HTMLElement {
  const receivable = vm.side === 'receivable';
  const c = card(t(receivable ? 'card.receivables' : 'card.payables'), 'wide');

  mount(c, big(vm.total.display, vm.tone));

  if (vm.buckets.length === 0) {
    mount(c, emptyNote(t(receivable ? 'ageing.empty.receivable' : 'ageing.empty.payable')));
    return c;
  }

  mount(
    c,
    el(
      'div',
      `sub ${vm.overdue.paise > 0 ? 'is-overdue' : ''}`,
      vm.overdue.paise > 0 ? t('ageing.overdue', { amount: vm.overdue.display }) : t('ageing.nothingOverdue'),
    ),
  );

  const body = el('div', 'ageing-body');

  /*
   * THE RING IS THE BUCKETS OF THE HEADLINE, OR THERE IS NO RING.
   *
   * `whole` is `vm.total.paise` — the very number printed in the ring's centre — and the buckets
   * are its parts. `donut()` verifies that they sum to it exactly, in integer paise, and refuses
   * to draw otherwise. That check is in `ringIsHonest`, not in this comment, because this
   * codebase's bugs cluster where the comments are most confident.
   *
   * The refusal is not an edge case to be swept up: it is a real business state and it gets a
   * real sentence. See `ringRefusal`.
   */
  const slices: Slice[] = vm.buckets.map((b) => ({
    paise: b.amount.paise,
    tone: b.tone,
    title: `${t(bucketKey(b.bucket))}: ${b.amount.display}`,
  }));
  const ring = donut(
    slices,
    vm.total.paise,
    `${t(receivable ? 'card.receivables' : 'card.payables')}: ${vm.total.display}`,
  );
  if (ring) {
    const wrap = el('div', 'donut-wrap');
    // The centre prints the ring's WHOLE, never a different quantity. `vm.total.compact` and the
    // `.big` above it are the same number in two renderings — exact and abbreviated — which is
    // a formatting choice, not a second claim. Putting `overdue` here (as this once did) made
    // the arcs sum to a number that was nowhere in the middle of them.
    mount(wrap, ring, donutCenter(vm.total.compact, t('ageing.total')));
    mount(body, wrap);
  } else {
    // The signed total, straight from the card layer. A sentence that needed the MAGNITUDE would
    // have to format money here, and this file is not allowed to.
    mount(body, emptyNote(t(ringRefusal(vm), { amount: vm.total.display })));
  }

  // Magnitudes are compared against the largest bucket, in paise. `Math.max(1, …)` guards the
  // all-zero case, where every share is 0/0.
  const peak = Math.max(1, ...vm.buckets.map((b) => Math.abs(b.amount.paise)));
  const bars = el('div', 'bars');
  for (const b of vm.buckets) {
    const row = el('div', 'bar-row');
    mount(
      row,
      dot(b.tone),
      el('span', 'bar-label', t(bucketKey(b.bucket))),
      bar(b.tone, Math.abs(b.amount.paise) / peak),
      el('span', 'bar-value', b.amount.compact),
    );
    row.setAttribute(
      'title',
      `${b.amount.display} · ${b.billCount === 1 ? t('ageing.oneBill') : t('ageing.bills', { n: b.billCount })}`,
    );
    mount(bars, row);
  }
  mount(body, bars);
  mount(c, body);

  if (vm.topParties.length > 0) {
    mount(c, el('h3', 'card-subtitle', t(receivable ? 'ageing.topDebtors' : 'ageing.topCreditors')));
    const rows = el('div', 'rows');
    for (const p of vm.topParties) {
      const row = el('div', 'row');
      // p.name is a party name typed by a human into a customer's Tally file. `A & B Traders
      // <Mumbai>` is an ordinary trade name and must render exactly as typed; an `<img
      // src=x onerror=…>` is a supplier's prerogative and must render as text. textContent is
      // the entire defence and it is not optional on this line.
      mount(
        row,
        el('span', p.isOthers ? 'row-name others' : 'row-name', p.isOthers ? t('ageing.everyoneElse') : p.name),
        el('span', `chip ${bucketTone(p.worstBucket)}`, t(bucketShortKey(p.worstBucket))),
        el('span', 'row-value', p.amount.display),
      );
      mount(rows, row);
    }
    mount(c, rows);
  }

  return c;
}

/**
 * WHY THERE IS NO RING — as a sentence the owner can act on, not an apology.
 *
 * A donut is refused only for reasons that are themselves worth knowing, so each one is stated
 * rather than smoothed over. This is the option chosen over the alternative of ringing the sum
 * of ABSOLUTE bucket magnitudes: that would always draw, and it would draw a whole that is not
 * the total on the card, in which a ₹4L advance and a ₹1L overdue debt become adjacent slices
 * of one pie as though they were the same kind of thing. It answers a question nobody asked
 * ("how is my gross exposure distributed") in the visual language of the question they did ask
 * ("what am I owed"). A business taking deposits being in net credit is unremarkable and
 * perfectly reportable in words; a chart that quietly redefines its own whole is not.
 */
function ringRefusal(vm: AgeingCard): StringKey {
  const receivable = vm.side === 'receivable';
  if (vm.total.paise < 0) {
    // Advances outweigh the book. The sentence carries the SIGNED total straight from the card
    // layer, so nothing here has to (or gets to) compute a magnitude.
    return receivable ? 'ageing.credit.receivable' : 'ageing.credit.payable';
  }
  if (vm.total.paise === 0) return 'ageing.netZero';
  // A positive book with an advance sitting inside one bucket. The bars show it, signed.
  return 'ageing.mixed';
}

function bucketKey(b: string): StringKey {
  return `bucket.${b}` as StringKey;
}

function bucketShortKey(b: string): StringKey {
  return `bucket.short.${b}` as StringKey;
}

/**
 * The tone for a PARTY's worst bucket.
 *
 * `AgeingCard.buckets[]` carries its own tone; `topParties[]` carries only `worstBucket`, so
 * this mirrors the card layer's mapping. Kept identical on purpose: a party whose worst bill is
 * 91–180 days must not get a different colour from the 91–180 bar directly above it.
 */
function bucketTone(b: string): Tone {
  if (b === 'not_due' || b === '0_30') return 'good';
  if (b === '31_60' || b === '61_90') return 'warn';
  return 'bad';
}

// ---------------------------------------------------------------- profit

export function renderProfit(vm: ProfitCard, t: T): HTMLElement {
  const c = card(t('card.profit'));
  mount(c, big(vm.current.display, vm.tone));

  const sub = el('div', 'sub');
  mount(
    sub,
    el('span', `delta ${vm.delta.direction}`, vm.delta.text),
    el('span', 'delta-vs', ` ${t('profit.vsLast', { amount: vm.previous.display })}`),
  );
  mount(c, sub);

  if (vm.current.paise === 0 && vm.previous.paise === 0) {
    mount(c, emptyNote(t('profit.empty')));
    return c;
  }

  // Two bars, last month against this one. The delta text says how much it moved; this says
  // whether that movement is a rounding error or the month.
  const columns: Column[] = [
    { paise: vm.previous.paise, label: t('profit.lastMonth'), title: vm.previous.display },
    { paise: vm.current.paise, label: t('profit.thisMonth'), title: vm.current.display, accent: true },
  ];
  mount(c, columnChart(columns, `${t('card.profit')}: ${vm.current.display}`));
  return c;
}

// ---------------------------------------------------------------- sales trend

export function renderTrend(vm: TrendCard, t: T, locale: Locale): HTMLElement {
  const c = card(t('card.sales'), 'wide');

  if (vm.points.length === 0) {
    mount(c, emptyNote(t('trend.none')));
    return c;
  }

  const last = vm.points.at(-1)!;
  mount(c, big(last.value.display, vm.tone));
  mount(
    c,
    el(
      'div',
      'sub',
      `${t('trend.subtitle', { n: vm.points.length })} · ${t('trend.peak', { amount: vm.peak.compact })}`,
    ),
  );

  if (vm.points.length < 2) {
    mount(c, emptyNote(t('trend.empty')));
    return c;
  }

  // The month label comes from `p.period` (`YYYY-MM`), not from `p.label`: the card layer's
  // label is English by construction and cannot be otherwise — it has no locale.
  const columns: Column[] = vm.points.map((p, i) => ({
    paise: p.value.paise,
    label: monthLabel(locale, p.period),
    title: p.value.display,
    accent: i === vm.points.length - 1,
  }));
  mount(c, columnChart(columns, `${t('card.sales')} · ${t('trend.subtitle', { n: vm.points.length })}`));
  return c;
}

// ---------------------------------------------------------------- stock

export function renderStock(vm: StockCard, t: T): HTMLElement {
  const c = card(t('card.stock'));
  mount(c, big(vm.total.display, vm.tone));

  if (vm.groups.length === 0) {
    mount(c, emptyNote(t('stock.empty')));
    return c;
  }

  const bars = el('div', 'bars');
  for (const g of vm.groups) {
    const row = el('div', 'bar-row');
    mount(
      row,
      dot('neutral'),
      el('span', 'bar-label', g.name),
      // `share` is already clamped to 0..1 by the card layer, which also handles negative stock
      // (real: issued before receipt). Do not recompute it here.
      bar('neutral', g.share),
      el('span', 'bar-value', g.value.compact),
    );
    row.setAttribute('title', `${g.name}: ${g.value.display}`);
    mount(bars, row);
  }
  mount(c, bars);
  return c;
}

// ---------------------------------------------------------------- balance sheet

/**
 * How many ROOT groups are drawn.
 *
 * Roots are normally the six or seven Tally ships with. They run into the hundreds only when
 * the pull was partial — `balanceSheetTree` surfaces a node whose parent is missing AT THE ROOT
 * rather than dropping it, precisely so that no group vanishes silently — and that is the case
 * where an unbounded loop paints thousands of rows nobody scrolls to.
 */
const SHEET_ROOT_BUDGET = 200;

/**
 * The balance sheet tree.
 *
 * NOT MOUNTED YET, AND THE REASON IS A MISSING FIELD RATHER THAN A MISSING DECISION.
 * `CompanyCards` (src/main/ipc.ts) carries cashBank, receivables, payables, profit, stock and
 * salesTrend — it does not carry the tree, and `getCards()` is the renderer's only data path.
 * `balanceSheetTree()` exists in the card layer and this renderer is written and tested against
 * it (see dashboard.cards.test.ts), so mounting it is one line in `paintContent` the moment
 * `CompanyCards` grows a `balanceSheet?: TreeNode[]`. Kept rather than deleted because the tree
 * is a required card and rewriting it later is pure waste; called out loudly rather than left
 * quiet because unmounted code that looks mounted is how a feature gets marked done twice.
 *
 * Amounts are RAW house convention — Dr negative, Cr positive — because `balanceSheetTree`
 * deliberately flips nothing: a balance sheet shows both sides at once, and choosing a flip per
 * node would mean trusting `primaryGroup`, which the flavour probe reports as EMPTY on installs
 * where `$_PrimaryGroup` is unavailable. Rather than guess and be silently wrong for some
 * installs, the card says what the sign means.
 *
 * CHILDREN ARE BUILT ONLY WHEN A NODE IS OPENED. A chart of accounts is a few hundred nodes for
 * a shop and several thousand for a distributor; building all of them on every repaint is a
 * frozen window every fifteen minutes, on the machine the owner is also running Tally on.
 */
export function renderSheet(nodes: readonly TreeNode[], t: T): HTMLElement {
  const c = card(t('card.sheet'), 'full');
  if (nodes.length === 0) {
    mount(c, emptyNote(t('sheet.empty')));
    return c;
  }

  /*
   * TWO SIDES, BOTH POSITIVE — because that is what a balance sheet IS, and what Tally itself
   * shows the owner.
   *
   * This card used to render the house convention raw: `Current Assets  -₹1,45,00,000`, under a
   * note explaining that assets show negative "which is Tally's own Dr/Cr convention". The note
   * was honest and the claim was subtly wrong. Dr/Cr signing is Tally's INTERNAL convention; its
   * own Balance Sheet screen puts Liabilities on the left and Assets on the right and shows both
   * as POSITIVE. So the dashboard was showing a businessman a figure his own accounting software
   * shows the other way round — and a minus in front of ₹1.45 crore reads, at 8am, to a
   * non-accountant, as being ₹1.45 crore in the hole. For a product briefed as "extremely easy",
   * that is the opposite.
   *
   * WHY IT WAS LEFT THAT WAY, and why that reasoning does not hold: `balanceSheetTree` flips
   * nothing because choosing a flip per node would mean trusting `primaryGroup` to say which
   * side a group is on, and the flavour probe reports `primaryGroup` EMPTY on installs where
   * `$_PrimaryGroup` is unavailable. Sound as far as it goes — but it misses that THE SIGN
   * ITSELF identifies the side. Dr (negative) is the asset side; Cr (positive) is the liability
   * side. Siding by sign needs `primaryGroup` for nothing at all.
   *
   * THE SUBTLETY THAT MAKES `Math.abs` WRONG: an overdrawn bank account is a CREDIT balance
   * sitting under Current Assets. Blind `abs` would print it as a positive asset — hiding an
   * overdraft, which is a worse lie than the one being fixed. So each side is normalised against
   * ITS ROOT's sign (`factor` below): a node that opposes its root still reads negative, exactly
   * as Tally shows an overdraft under Assets.
   *
   * NIL-BALANCE ROOTS get their own line rather than a guess. A root whose closing balance is
   * exactly zero cannot be sided by sign, and there is no other signal this card trusts — so
   * putting it under "Assets" would be inventing information. It holds no money, so a name is
   * all it needs.
   */
  const roots = nodes.slice(0, SHEET_ROOT_BUDGET);
  const assets = roots.filter((n) => n.amount.paise < 0);
  const liabilities = roots.filter((n) => n.amount.paise > 0);
  const nil = roots.filter((n) => n.amount.paise === 0);

  mount(c, el('div', 'sub', t('sheet.hint')));

  const sides = el('div', 'sheet-sides');
  // `-1` for assets: the side is normalised so its root reads positive. See above.
  if (assets.length > 0) mount(sides, sheetSide(t('sheet.assets'), assets, -1, t));
  if (liabilities.length > 0) mount(sides, sheetSide(t('sheet.liabilities'), liabilities, 1, t));
  mount(c, sides);

  if (nil.length > 0) {
    mount(c, el('div', 'sheet-nil', t('sheet.nil', { names: nil.map((n) => n.name).join(', ') })));
  }
  return c;
}

/** One side of the sheet. `factor` normalises it so the side's own roots read positive. */
function sheetSide(
  heading: string,
  roots: readonly TreeNode[],
  factor: 1 | -1,
  t: T,
): HTMLElement {
  const side = el('div', 'sheet-side');
  mount(side, el('h3', 'sheet-side-title', heading));

  // The side's own total, so the owner gets the number without expanding anything. Summed in
  // PAISE — exact integers — and only then divided for display; summing `raw` rupees would be
  // adding floats, which is the one thing the money discipline forbids.
  const totalPaise = roots.reduce((sum, n) => sum + n.amount.paise, 0);
  mount(side, big(formatMoney((totalPaise * factor) / 100), 'neutral'));

  const tree = el('div', 'tree');
  tree.setAttribute('role', 'tree');
  for (const n of roots) mount(tree, treeRow(n, 0, factor));
  mount(side, tree);
  return side;
}

function treeRow(node: TreeNode, depth: number, factor: 1 | -1): HTMLElement {
  const wrap = el('div', 'tree-node');
  const row = el('div', 'tree-row');
  setVar(row, '--depth', String(depth));

  const kids = el('div', 'tree-children');
  let open = false;
  let built = false;

  const hasChildren = node.children.length > 0;
  const caret = el('span', 'caret', hasChildren ? '▸' : '');
  caret.setAttribute('aria-hidden', 'true');

  const label = el('span', 'tree-name', node.name);

  /*
   * Normalised to its SIDE, not to zero.
   *
   * `shown` is the amount as this side reads it: positive when the node agrees with its root,
   * NEGATIVE when it opposes — an overdrawn bank under Current Assets, a supplier who is in
   * credit under Sundry Creditors. That minus sign is information, and `Math.abs` would delete
   * exactly the entries an owner most needs to see.
   *
   * The tone follows `shown`, not the raw Dr/Cr: on a sided view, "negative" means "against the
   * grain of this side", which is what the colour should say.
   *
   * `paise * factor / 100` rather than `raw * factor`: `paise` is an exact integer and the
   * division is the single rounding step, which is the money rule this codebase pins. Formatting
   * goes through `formatMoney` — never `Intl.NumberFormat('en-IN')`, which silently falls back
   * to en-US grouping without full ICU and prints `₹1,42,34,110` as `₹14,234,110`.
   */
  const shownPaise = node.amount.paise * factor;
  const value = el(
    'span',
    `tree-value ${shownPaise < 0 ? 'dr' : 'cr'}`,
    formatMoney(shownPaise / 100),
  );

  if (hasChildren) {
    const b = button('tree-toggle', '', () => {
      open = !open;
      if (open && !built) {
        built = true;
        // Deferred until first open — see renderSheet. The factor rides down so a child is
        // normalised to the same side as the root it hangs from.
        for (const child of node.children) mount(kids, treeRow(child, depth + 1, factor));
      }
      kids.classList.toggle('open', open);
      caret.textContent = open ? '▾' : '▸';
      b.setAttribute('aria-expanded', String(open));
    });
    b.setAttribute('aria-expanded', 'false');
    mount(b, caret, label, value);
    mount(row, b);
  } else {
    mount(row, el('span', 'caret leaf'), label, value);
  }

  mount(wrap, row, kids);
  return wrap;
}

// ---------------------------------------------------------------- grid
//
// `renderInto(root, cards)` USED TO LIVE HERE AND IS DELETED ON PURPOSE.
//
// It was "the shell's entry point into this file", and its one caller was `main.ts`, which
// called it as `renderInto(content, [])` — with a literal empty array, after fetching the cards
// and discarding them. That is how the entire dashboard stayed off the screen while
// `mountDashboard` accumulated thirty passing tests: the app had an entry point into the card
// file that rendered a grid of nothing, and it looked like wiring.
//
// The grid is now built by `paintContent` in dashboard.ts, which is the only thing that knows
// which cards exist and in what order. Nothing should re-introduce a general "put these nodes
// in a grid" helper here: it has no caller, it invites the shell to assemble the dashboard a
// second way, and a second way is what took the first one four months to notice.
