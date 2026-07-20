import type { BridgeApi, GetCardsResult } from '../main/ipc.ts';
import type { SyncStatus } from '../main/scheduler.ts';
import {
  renderAgeing,
  renderCashBank,
  renderEmpty,
  renderProfit,
  renderSheet,
  renderStock,
  renderTrend,
} from './cards.ts';
import { button, clear, el, mount } from './dom.ts';
import { LOCALES, LOCALE_NAMES, dateLabel, isLocale, relativeTime, translator, type Locale, type T } from './i18n.ts';
import { buildModel, hasNoCards, type DashboardModel } from './snapshot.ts';

/**
 * THE DASHBOARD.
 *
 * The screen the product exists to show: how much cash do I have, who owes me money, am I
 * making a profit — inside five seconds, at 8am, with chai.
 *
 * Mount it once and leave it:
 *
 *     import { mountDashboard } from './dashboard.ts';
 *     const dash = mountDashboard(container);   // container is any empty element
 *     // later, if the shell tears the view down:
 *     dash.destroy();
 *
 * It owns its own data: it calls `window.bridge` itself rather than being handed a model,
 * because the freshness of a number and the number itself are the same fact, and splitting
 * them across two owners is how a stale figure ends up under a green checkmark. The bridge is
 * injectable so this is testable without Electron.
 */

export interface DashboardOptions {
  /** Defaults to `window.bridge`. Injected by tests. */
  bridge?: BridgeApi;
  now?: () => number;
  locale?: Locale;
  /**
   * Draw the sync strip (status, freshness, language, "Sync now") above the grid. Default true.
   * Pass false only if the shell already renders an equivalent strip — the RULE is that the
   * owner can always see how old these numbers are, not that this file is the one drawing it.
   */
  chrome?: boolean;
  /**
   * Called when the data is locked and the owner asks to unlock.
   *
   * The passphrase prompt belongs to the shell, not here — it is the same prompt onboarding
   * already owns, and two implementations of a passphrase field is one too many. Without this
   * the locked state still says what is true; it just offers no button.
   */
  onUnlockRequested?: () => void;
}

export interface DashboardHandle {
  /** Re-fetch status and cards, and repaint. Never rejects. */
  refresh(): Promise<void>;
  /** For a shell that already subscribes to `onStatusChanged` and wants to forward it. */
  setStatus(status: SyncStatus): void;
  setLocale(locale: Locale): void;
  destroy(): void;
}

/**
 * EVERY IPC CALL CAN REJECT, AND A REJECTION MUST NOT REACH THE SCREEN.
 *
 * `ipcRenderer.invoke` rejects whenever the main-process handler throws, and it does: the
 * scheduler surfaces Tally and network failures through exactly these paths. An unhandled
 * rejection does not show an error, it shows NOTHING — the await never resumes and a
 * half-painted card sits there forever. Note also that `.finally()` does NOT handle a
 * rejection; it re-throws after running, which is how a "Sync now" button once stayed on
 * "Syncing…" for the rest of the session.
 *
 * So the fallback is a VALUE, never a rethrow, and every call goes through here.
 */
async function ask<T>(call: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await call();
  } catch (e) {
    // The console is for whoever is debugging. The owner gets a sentence and a button.
    console.error('[dashboard] IPC failed:', e);
    return fallback;
  }
}

const UNREACHABLE: SyncStatus = {
  state: 'error',
  message: 'Tally Bridge is not responding. Restarting the app usually fixes this.',
  action: 'Try again',
};

const LOCALE_STORAGE_KEY = 'tally-bridge.locale';

/** Remembering the language is worth exactly zero crashes. */
function storedLocale(): Locale | undefined {
  try {
    const v = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return isLocale(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

function rememberLocale(locale: Locale): void {
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // Storage disabled or full. The language still applies for this session.
  }
}

export function mountDashboard(container: Element, options: DashboardOptions = {}): DashboardHandle {
  const bridge = options.bridge ?? window.bridge;
  const now = options.now ?? (() => Date.now());
  const chrome = options.chrome ?? true;

  let locale: Locale = options.locale ?? storedLocale() ?? 'en';
  let t: T = translator(locale);
  let status: SyncStatus = { state: 'never', message: 'Not synced yet' };
  let model: DashboardModel | undefined;
  let selectedGuid: string | undefined;
  let syncing = false;
  let destroyed = false;
  /**
   * Watches every card for a height change, so the masonry spans stay true. See layoutMasonry.
   * Mount-scoped and disconnected in destroy() — an observer that outlives its grid keeps the
   * whole detached tree alive and re-lays-out nodes nobody can see.
   */
  let ro: ResizeObserver | undefined;
  /**
   * THE REQUEST SEQUENCE. Every `refresh()` takes a ticket; only the newest may commit.
   *
   * `refresh()` is called from four places — the mount, the company picker, the error card's
   * "Try again", `sync()`, and the shell through the exported handle — none of which wait for
   * the others, and `ipcRenderer.invoke` over a busy single-threaded main process does NOT
   * answer in call order. Without this, a slow OLD payload lands after a fast NEW one and
   * overwrites it: the owner reads last week's receivables under this morning's green
   * checkmark, which is precisely the failure this file exists to prevent.
   */
  let requestSeq = 0;
  /** Held so a status push can retone the grid without rebuilding it. */
  let gridEl: HTMLElement | undefined;

  clear(container);
  container.classList.add('dashboard');

  const strip = el('div', 'sync-strip');
  const banners = el('div', 'banners');
  const content = el('div', 'dash-content');
  mount(container, ...(chrome ? [strip] : []), banners, content);

  mount(content, skeleton());

  // ------------------------------------------------------------ the sync strip

  function paintStrip(): void {
    if (!chrome) return;
    clear(strip);

    // The dot is never the only signal — the sentence beside it says the same thing in words.
    // Roughly one in twelve Indian men is red/green colourblind, and this app is mostly read by
    // men over forty-five.
    const d = el('span', `dot ${status.state}`);
    d.setAttribute('aria-hidden', 'true');
    mount(strip, d);

    const text =
      status.state === 'ok'
        ? t('status.synced', { when: relativeTime(locale, status.lastRun, now()) })
        : status.state === 'never'
          ? t('status.never')
          : // `describeStatus` in the main process guarantees this is a sentence for a human and
            // never a code or a stack. This just shows it.
            status.message;
    const line = el('span', 'status-text', text);
    // Announce a change of state, but do not interrupt: this updates every minute.
    line.setAttribute('role', 'status');
    mount(strip, line);

    // "Figures as of 16 Jul 2026" — the date the DATA is from, which is a different fact from
    // when the sync ran and is the one an accountant asks for. Both are on this strip.
    if (model?.cards?.asOf) {
      mount(strip, el('span', 'as-of', t('freshness.asOf', { date: dateLabel(locale, model.cards.asOf) })));
    }

    mount(strip, languageToggle());

    // Every state carries exactly one action, and it is never a dead end. `status.action` is
    // "Open Tally" / "Try again" — the app cannot launch Tally for the owner (there is no IPC
    // verb for it, and `openExternal` is allowlisted to the deployment host), so the button
    // re-checks, which is the thing this app CAN do and the thing they want next.
    const label = syncing
      ? t('status.syncing')
      : status.state === 'waiting' || status.state === 'error'
        ? status.action
        : t('action.sync');
    const b = button('status-action primary', label, () => void sync());
    b.disabled = syncing;
    mount(strip, b);
  }

  function languageToggle(): HTMLElement {
    const group = el('div', 'lang');
    group.setAttribute('role', 'group');
    for (const l of LOCALES) {
      const b = button(l === locale ? 'lang-option on' : 'lang-option', LOCALE_NAMES[l], () => setLocale(l));
      b.setAttribute('aria-pressed', String(l === locale));
      // The name of a language is always written in that language, never translated. Someone
      // looking for their own language is scanning for the word they know.
      b.setAttribute('lang', l);
      mount(group, b);
    }
    return group;
  }

  async function sync(): Promise<void> {
    if (syncing) return;
    syncing = true;
    paintStrip();
    // `ask` swallows the rejection and returns, so the button always comes back. This is the
    // exact line that used to be a `.finally()`.
    await ask(() => bridge.syncNow(), undefined);
    syncing = false;
    await refresh();
  }

  // ------------------------------------------------------------ banners

  function paintBanners(): void {
    clear(banners);

    // THE RULE: never look confident about old data. If the last sync did not succeed, the
    // numbers below are from some earlier one, and saying so in a sentence — not just with an
    // amber dot in a corner — is the difference between a dashboard and a liability.
    if (model?.state === 'ready' && status.state !== 'ok') {
      mount(banners, el('div', 'banner warn', t('freshness.stale')));
    }
    // `incomplete` means a section or a card was skipped upstream. The cards that DID arrive
    // must not be allowed to imply they are the whole picture.
    if (model?.state === 'ready' && model.incomplete) {
      mount(banners, el('div', 'banner bad', t('error.cards')));
    }
  }

  // ------------------------------------------------------------ the grid

  function paintContent(): void {
    clear(content);
    gridEl = undefined;

    if (!model) {
      mount(content, skeleton());
      return;
    }

    // EVERY NON-READY STATE IS A SENTENCE AND AT MOST ONE ACTION. Never a code, never a stack,
    // and never a blank screen that the owner has to interpret.
    switch (model.state) {
      case 'locked':
        mount(
          content,
          renderEmpty(
            // `problem` is set only when the last unlock failed for a reason that is provably
            // NOT the passphrase, so it is safe to show verbatim. Usually there is none, and
            // "locked" is simply the truth with no drama attached.
            model.message ?? t('locked.body'),
            options.onUnlockRequested ? t('locked.action') : undefined,
            options.onUnlockRequested,
          ),
        );
        return;

      case 'empty':
        mount(
          content,
          // Tally being closed is not an error, it is a Sunday. If that is why there is nothing
          // yet, say THAT rather than the generic line.
          renderEmpty(status.state === 'waiting' ? status.message : t('empty.all')),
        );
        return;

      case 'error':
        // The main process guarantees one plain sentence here.
        mount(content, renderEmpty(model.message ?? t('error.generic'), t('action.retry'), () => void refresh()));
        return;

      case 'unavailable':
        mount(content, renderEmpty(t('error.unreachable'), t('action.retry'), () => void refresh()));
        return;

      case 'ready':
        break;
    }

    const cards = model.cards;
    if (hasNoCards(cards)) {
      // Unlocked, synced, and genuinely nothing in it — a brand-new company. Not an error.
      mount(content, renderEmpty(t('empty.all')));
      return;
    }

    if (model.companies.length > 1) mount(content, companyPicker());

    const grid = el('div', 'grid');

    /*
     * The order is the order of the questions, and it is the whole design of this screen:
     * how much money have I got, am I making a profit, who owes me, who do I owe, how are sales
     * going, what is on the shelf. The first two are the five-second answer and they sit top-left
     * where the eye lands; receivables is wide because "who owes me most" is the reason this app
     * was bought.
     *
     * A card is simply ABSENT when its section has not synced or could not be opened — that is a
     * state the contract defines and it is not an error. It costs its slot and nothing else; the
     * `incomplete` banner above is what tells the owner that the picture is partial.
     */
    if (cards?.cashBank) mount(grid, renderCashBank(cards.cashBank, t));
    if (cards?.profit) mount(grid, renderProfit(cards.profit, t));
    if (cards?.receivables) mount(grid, renderAgeing(cards.receivables, t));
    if (cards?.payables) mount(grid, renderAgeing(cards.payables, t));
    if (cards?.salesTrend) mount(grid, renderTrend(cards.salesTrend, t, locale));
    if (cards?.stock) mount(grid, renderStock(cards.stock, t));
    // LAST, and that is the design rather than an afterthought. Everything above answers a
    // question at a glance; the balance sheet is the one card the owner READS, by expanding the
    // groups they care about. It goes where the eye arrives after the five-second answers, and
    // `renderSheet` builds children lazily on open — a distributor's chart of accounts is
    // several thousand nodes, and painting all of them every fifteen minutes would freeze the
    // window on the same PC that is running Tally.
    //
    // `?.length` for the same reason as `hasNoCards`: an empty tree is a heading over nothing.
    if (cards?.balanceSheet?.length) mount(grid, renderSheet(cards.balanceSheet, t));

    // Desaturate the numbers when they are not current. The banner says it in words; this makes
    // it impossible to glance past.
    if (status.state !== 'ok') grid.classList.add('stale');

    gridEl = grid;
    mount(content, grid);
    layoutMasonry(grid);
  }

  /**
   * Give every card a row span equal to the height it actually wants.
   *
   * WHY THIS IS NOT CSS'S JOB (yet). A grid row is as tall as its tallest item, so Cash (~230px)
   * sharing row 1 with Receivables (~500px: donut plus five debtors) sat at the top of a 500px
   * row with ~270px of void beneath it. On the 1366×768 screen this product is actually used on,
   * about 40% of the first screen was empty and Payables was below the fold. Nothing caught it:
   * the tests render into a fake DOM that has no layout at all, so the first screenshot ever
   * taken of this app was also the first evidence of it.
   *
   * `grid-template-rows: masonry` would do this natively and is Firefox-only; this app is
   * Chromium. `columns:` masonry works everywhere but flows top-to-bottom-then-across, which
   * would drop Cash, Profit and Receivables down one column instead of across the top where the
   * eye lands — the card ORDER is the design (see paintContent), so that is not available
   * either. Fine rows plus a computed span is the technique that survives both constraints.
   *
   * Setting `.style` from script is NOT blocked by our `style-src 'self'` CSP: that directive
   * governs `<style>` elements and `style=""` attributes in parsed markup, not CSSOM writes.
   * (Checked, because getting it wrong means a dashboard that silently refuses to lay out.)
   */
  function layoutMasonry(grid: HTMLElement): void {
    /*
     * LAYOUT IS AN ENHANCEMENT. THE NUMBERS ARE NOT.
     *
     * Everything below needs a real layout engine — `getComputedStyle`, `scrollHeight`,
     * `ResizeObserver`. In Electron all three exist; but this function is one `paintContent`
     * away from the code that puts an owner's cash balance on screen, and a dashboard that
     * THROWS because a spacing helper is unavailable is immeasurably worse than one that is
     * spaced by the CSS fallback (`.grid > * { grid-row-end: span 40 }`).
     *
     * This is not hypothetical politeness: the test suite renders into a fake DOM with no
     * layout at all (test/dashboard.dom.ts), and without this guard six tests — including
     * "STALE DATA IS NEVER SHOWN UNDER A GREEN CHECKMARK" — died on a missing global. The tests
     * found the real requirement: measure if you can, render regardless.
     */
    if (typeof ResizeObserver !== 'function' || typeof window.getComputedStyle !== 'function') {
      return;
    }

    // A CARD'S HEIGHT IS NOT FIXED AFTER THE FIRST PASS, so a one-shot measurement rots:
    //   - the balance sheet builds its children ON OPEN (renderSheet, deliberately — a
    //     distributor's chart of accounts is thousands of nodes), so expanding a group makes the
    //     card taller than the span we just gave it and it would clip its own contents;
    //   - the window resizes, and re-wrapping a 47-character party name changes a card's height
    //     without changing anything we could hook;
    //   - the language toggle swaps every string for Devanagari, which has a taller line box.
    //
    // ResizeObserver catches all three by watching the thing that actually changed, rather than
    // by guessing at the events that might cause it. It is disconnected in destroy().
    if (!ro) {
      ro = new ResizeObserver(() => {
        // Re-measure from the grid we are observing, not a captured one: paintContent builds a
        // NEW grid element on every repaint.
        if (gridEl) relayout(gridEl);
      });
    }
    ro.disconnect();
    for (const child of Array.from(grid.children)) ro.observe(child);
    relayout(grid);
  }

  function relayout(grid: HTMLElement): void {
    const styles = window.getComputedStyle(grid);
    const row = parseFloat(styles.getPropertyValue('grid-auto-rows')) || 8;
    const gap = parseFloat(styles.getPropertyValue('column-gap')) || 16;

    for (const child of Array.from(grid.children)) {
      const card = child as HTMLElement;
      // `scrollHeight`, not `getBoundingClientRect().height`: the card's own height is already
      // constrained by the span we are about to compute (or by the CSS fallback), so measuring
      // the rendered box would just measure our own previous guess and converge on it. The
      // scroll height is what the content wants regardless.
      const wanted = card.scrollHeight;
      // +gap so the span carries its own bottom margin — row-gap is 0 by necessity (an 8px row
      // gap would appear between every one of the ~60 rows a card spans, not between cards).
      const span = Math.max(1, Math.ceil((wanted + gap) / row));
      const next = `span ${span}`;

      // Write only on change. A cheap guard, and — HAVING MEASURED IT — NOT the thing that keeps
      // this ResizeObserver from looping. I wrote a confident comment here claiming it was, then
      // tested the claim by deleting the guard: the layout still converges and Chromium still
      // logs zero "ResizeObserver loop completed with undelivered notifications". The comment was
      // wrong, so it is gone. (Recording the correction rather than quietly deleting it, because
      // the next person will have the same intuition I did.)
      //
      // WHAT ACTUALLY PREVENTS THE LOOP is `align-self: start` on `.card` (styles.css). It
      // decouples a card's HEIGHT from its row span: the span reserves grid space, while the
      // card's box stays exactly as tall as its content. So writing `gridRowEnd` does not resize
      // the observed box, no notification is generated, and there is no cycle to break. Remove
      // `align-self: start` and this genuinely would feed back — which is the real reason to
      // leave both in place.
      //
      // Measured: spans settle to a fixed vector and are byte-identical 2s later, with and
      // without this guard. The ~3.5k loop warnings the screenshot harness prints come from the
      // harness resizing its own window to 4000px for the full-page capture, not from the app.
      if (card.style.gridRowEnd !== next) card.style.gridRowEnd = next;
    }
  }

  function companyPicker(): HTMLElement {
    const wrap = el('div', 'companies');
    wrap.setAttribute('role', 'group');
    wrap.setAttribute('aria-label', t('company.switch'));
    for (const c of model?.companies ?? []) {
      // c.name comes out of the customer's Tally file. textContent, always.
      const b = button(c.guid === model?.selected ? 'company on' : 'company', c.name, () => {
        selectedGuid = c.guid;
        void refresh();
      });
      b.setAttribute('aria-pressed', String(c.guid === model?.selected));
      mount(wrap, b);
    }
    return wrap;
  }

  function paint(): void {
    if (destroyed) return;
    paintStrip();
    paintBanners();
    paintContent();
  }

  // ------------------------------------------------------------ data

  async function refresh(): Promise<void> {
    if (destroyed) return;
    const seq = ++requestSeq;

    const nextStatus = await ask(() => bridge.getStatus(), UNREACHABLE);
    // `null` is not a state the wire can report — it is what `ask` returns when the call itself
    // rejected. `buildModel` turns it into `unavailable`, which has its own sentence, rather
    // than letting it read as "no data yet".
    const payload = await ask<GetCardsResult | null>(() => bridge.getCards(), null);
    if (destroyed) return;
    // A newer refresh has already answered. Drop this one whole — its status and its cards are
    // a matched pair, and committing either half over a newer answer is a desynchronised
    // dashboard. Dropping is safe: the newer answer painted everything this one would have.
    if (seq !== requestSeq) return;

    // Assigned TOGETHER, after both calls have landed. `status` used to be assigned the moment
    // getStatus resolved, which left a window where the strip showed this refresh's freshness
    // over the previous refresh's numbers.
    status = nextStatus;
    model = buildModel(payload, selectedGuid);
    selectedGuid = model.selected;
    paint();
  }

  function setLocale(next: Locale): void {
    if (next === locale) return;
    locale = next;
    t = translator(locale);
    rememberLocale(locale);
    document.documentElement.setAttribute('lang', locale);
    paint();
  }

  function setStatus(next: SyncStatus): void {
    status = next;
    // Only the chrome and the staleness treatment depend on status; the numbers do not, so a
    // status push must not rebuild the whole grid. It fires on every cycle.
    paintStrip();
    paintBanners();
    gridEl?.classList.toggle('stale', status.state !== 'ok');
  }

  document.documentElement.setAttribute('lang', locale);

  let unsubscribe: (() => void) | undefined;
  try {
    unsubscribe = bridge.onStatusChanged(setStatus);
  } catch (e) {
    // The preload caps the listener count and throws past it. A dashboard that cannot subscribe
    // still polls below; it must not fail to mount over this.
    console.error('[dashboard] could not subscribe to status:', e);
  }

  // Re-render the relative timestamp without re-fetching. A minute is the resolution the string
  // actually has ("2 min ago"), so anything faster is wasted work on a machine that is also
  // running Tally.
  const ticker = setInterval(() => {
    if (status.state === 'ok') paintStrip();
  }, 60_000);

  void refresh();

  return {
    refresh,
    setStatus,
    setLocale,
    destroy() {
      destroyed = true;
      clearInterval(ticker);
      unsubscribe?.();
      // An observer that outlives its grid holds the whole detached tree alive and keeps
      // re-laying-out nodes nobody can see. `clear(container)` drops the DOM but NOT the
      // observation.
      ro?.disconnect();
      ro = undefined;
      clear(container);
    },
  };
}

/**
 * The first paint, before any IPC has answered.
 *
 * Card-shaped grey blocks rather than a spinner: the layout does not jump when the data lands,
 * which is most of what makes an app feel fast rather than merely be fast. It is also honest —
 * it shows nothing, where a spinner over stale numbers would show something wrong.
 */
function skeleton(): HTMLElement {
  const grid = el('div', 'grid');
  for (const width of ['normal', 'normal', 'wide', 'wide'] as const) {
    const c = el('div', `card ${width} skeleton`);
    c.setAttribute('aria-hidden', 'true');
    mount(c, el('div', 'sk sk-title'), el('div', 'sk sk-big'), el('div', 'sk sk-line'), el('div', 'sk sk-line'));
    mount(grid, c);
  }
  return grid;
}
