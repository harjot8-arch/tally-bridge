import type { BridgeApi, GetCardsResult, MobileAccess } from '../main/ipc.ts';
import type { SyncStatus } from '../main/scheduler.ts';
import {
  renderAgeing,
  renderCashBank,
  renderDutiesTaxes,
  renderEmpty,
  renderMobileAccess,
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
  /** The phone-access details (URL, Tally ID, QR). Constant once provisioned; fetched in refresh. */
  let mobileAccess: MobileAccess | null = null;
  let syncing = false;
  let destroyed = false;
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
     * THE BENTO — rows of panels separated by 1px hairline gaps (see `.grid` in styles.css).
     *
     * The order is the order of the questions, and the ROW SHAPE says which question is biggest:
     *
     *   .lede — the HERO: Cash & Bank at 2fr (the first question of the morning, with the
     *           biggest number on the screen) beside Profit at 1fr.
     *   .pair — the two AGEING books the app was bought for, side by side.
     *   .trio — Sales trend, Stock, GST: the monthly rhythm.
     *   .solo — LAST, the balance sheet, full width — the one card an owner READS, expanding
     *           groups on demand (`renderSheet` builds children lazily on open).
     *
     * A card is simply ABSENT when its section did not sync — a defined state, not an error.
     * `auto-fit` on pair/trio and `:only-child` on the lede mean a missing card widens its
     * neighbours instead of leaving a grey void. The `incomplete` banner above is what says the
     * picture is partial.
     */
    const addRow = (kind: 'lede' | 'pair' | 'trio' | 'solo', rowCards: HTMLElement[]): void => {
      if (rowCards.length === 0) return;
      const row = el('div', `grid-row ${kind}`);
      mount(row, ...rowCards);
      mount(grid, row);
    };

    const lede: HTMLElement[] = [];
    if (cards?.cashBank) {
      const hero = renderCashBank(cards.cashBank, t);
      // The hero class scales the number up and draws the one gold hairline. Set here, not in
      // the render function: which card leads is this layout's decision, not the card's.
      hero.classList.add('hero');
      lede.push(hero);
    }
    if (cards?.profit) lede.push(renderProfit(cards.profit, t));
    addRow('lede', lede);

    const books: HTMLElement[] = [];
    if (cards?.receivables) books.push(renderAgeing(cards.receivables, t));
    if (cards?.payables) books.push(renderAgeing(cards.payables, t));
    addRow('pair', books);

    // Sales at a third of the width keeps the 340-wide chart near the ~330px it was tuned for.
    const rhythm: HTMLElement[] = [];
    if (cards?.salesTrend) rhythm.push(renderTrend(cards.salesTrend, t, locale));
    if (cards?.stock) rhythm.push(renderStock(cards.stock, t));
    if (cards?.dutiesTaxes) rhythm.push(renderDutiesTaxes(cards.dutiesTaxes, t));
    addRow('trio', rhythm);

    if (cards?.balanceSheet?.length) addRow('solo', [renderSheet(cards.balanceSheet, t)]);

    // The same figures on the owner's phone, via the web dashboard they deployed. A full-width
    // row at the foot: it is an ACTION (set up your phone), not a figure, so it sits after the
    // numbers rather than among them. Absent until the deployment exists.
    if (mobileAccess) {
      addRow('solo', [renderMobileAccess(mobileAccess, t, (url) => void bridge.openExternal(url))]);
    }

    // Mark the grid stale when the numbers are not current. The BANNER carries the message in
    // words; this class is a styling hook and a test surface, deliberately without a heavy
    // visual treatment — greying out the owner's real (if older) numbers read as "broken".
    if (status.state !== 'ok') grid.classList.add('stale');

    gridEl = grid;
    mount(content, grid);
  }

  /*
   * (Masonry retired.) This file used to give every card a `grid-row-end` span computed from its
   * measured height, via a ResizeObserver, because a grid row is as tall as its tallest item and a
   * short card next to the tall Receivables card left a ~270px void. paintContent now groups cards
   * into rows of like-height peers that share a height (`align-items: stretch`), so the void — and
   * the ragged, patchy packing an owner reported as "not placed evenly" — is designed out rather
   * than measured away. No layout JS, no observer loop warnings, and the balance sheet is free to
   * grow when a group is expanded because nothing pins its height.
   */

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
    // Phone-access details. Constant once provisioned, so the previous value is the fallback — a
    // transient IPC failure must not blank a card that was showing a moment ago. `ask` swallows
    // the TypeError if a test's fake bridge omits the (optional) method.
    const nextMobile = await ask<MobileAccess | null>(
      () => (bridge.getMobileAccess ? bridge.getMobileAccess() : Promise.resolve(null)),
      mobileAccess,
    );
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
    mobileAccess = nextMobile;
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
