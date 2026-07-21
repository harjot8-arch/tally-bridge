import { renderEmpty } from './cards.ts';
import { button, clear, el, mount } from './dom.ts';
import { mountDashboard, type DashboardHandle } from './dashboard.ts';
import { decideContent, startWizard } from './wizard.ts';
import { isLocale, translator, type Locale } from './i18n.ts';

/**
 * The renderer entry point.
 *
 * Reads only from `window.bridge`, the enumerated preload API. It has no network access
 * (CSP `connect-src 'none'`), no Node, and no filesystem — a compromise here reaches nothing.
 *
 * ## What this file is, and what it deliberately is not
 *
 * It is a ROUTER, and nothing else. Exactly one of two things owns the screen:
 *
 *   the WIZARD     — setup is not finished
 *   the DASHBOARD  — setup is finished
 *
 * It draws no cards, no status strip, and no chrome of its own. That is not minimalism for its
 * own sake; it is the fix for two bugs that both came from this file trying to be a third UI.
 *
 * ### Bug one: the dashboard was never on screen
 *
 * This file used to fetch the cards and then call `renderInto(content, [])` — an EMPTY ARRAY.
 * Meanwhile `mountDashboard` — six cards, the ageing donut, the sales trend, the balance sheet,
 * the freshness strip, request sequencing — had thirty call sites in the test suite and NOT ONE
 * in `src`. Every one of those tests passed, for months, over a dashboard no owner could ever
 * see, because a test that mounts a component is not evidence that the app mounts it.
 *
 * That is the third time this exact shape has appeared in this codebase (the reader had no
 * caller; the balance sheet had no field). The lesson each time is the same: a component's tests
 * prove it WORKS, never that it RUNS. Only a caller does that.
 *
 * ### Bug two: the status bar destroyed the recovery sheet
 *
 * This file also mounted its own status strip OUTSIDE the content area, so it stayed live during
 * setup with a "Sync now" button on it — and every button on it called `refresh()`. Since
 * `isProvisioned()` flips during the WRAP (two screens before the wizard finishes), a single
 * click while the recovery sheet was on screen disposed the wizard for good. See `decideContent`
 * in wizard.ts for the full account.
 *
 * Both bugs are the same mistake: this file rendering things that already had an owner. So now
 * the wizard owns the screen during setup — no strip, no button, nothing to click — and
 * `mountDashboard` draws its own strip afterwards, because freshness and the numbers are one
 * fact and splitting them across two owners is how a stale figure ends up under a green tick.
 */

const root = document.getElementById('root')!;

let content: HTMLElement | undefined;

/**
 * The wizard owns `content` while it is mounted, and this handle is how the shell knows to keep
 * its hands off — a promise this file previously made in a comment and then broke, by using this
 * very handle to dispose the wizard mid-recovery-sheet. `decideContent` now enforces it.
 *
 * Re-mounting is equally forbidden: the passphrase and the two recovery words live in DOM
 * inputs, not in state, so a repaint would silently wipe a half-typed passphrase.
 */
let disposeWizard: (() => void) | undefined;

/** The live dashboard, when setup is done. Mounted once and kept — it refreshes itself. */
let dashboard: DashboardHandle | undefined;

/**
 * EVERY IPC CALL CAN REJECT, AND NONE OF THEM HANDLED IT.
 *
 * `ipcRenderer.invoke` rejects whenever the main-process handler throws — and it can: the
 * scheduler surfaces Tally and network failures through exactly these paths. An unhandled
 * rejection here does not show an error, it shows NOTHING: the await never resumes, so a
 * half-painted UI freezes with no message. That is the worst outcome for a dashboard whose one
 * job is to tell an owner whether the numbers are current.
 *
 * So no bridge call is made without a fallback. The fallback is a VALUE, not a rethrow.
 */
async function ask<T>(call: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await call();
  } catch (e) {
    // The main process is the only thing on the other end; if it is failing, the console is
    // where an engineer looks. The owner gets the fallback rendering, never a stack.
    console.error('[bridge] IPC failed:', e);
    return fallback;
  }
}

/**
 * Decide who owns the screen, and hand it over.
 *
 * Runs on boot and whenever setup finishes. It does NOT run on every status push — the dashboard
 * subscribes to those itself and repaints in place, which is the whole reason it can keep a
 * company selection and a scroll position.
 */
async function route(): Promise<void> {
  if (!content) return;

  // Fail CLOSED: if we cannot tell whether setup is done, show the setup path rather than an
  // empty dashboard that implies there is simply no data. `decideContent` treats anything that
  // is not literally `true` — a rejected call's fallback, a half-loaded value — as "not set up".
  const provisioned = await ask<unknown>(() => window.bridge.isProvisioned(), false);

  switch (decideContent(disposeWizard !== undefined, provisioned)) {
    case 'wizard-owns-content':
      // A live wizard outranks the flag, always. This is the guard that keeps the recovery
      // sheet on screen; see decideContent.
      return;

    case 'show-wizard':
      showWizard(content);
      return;

    case 'show-dashboard':
      showDashboard(content);
      return;
  }
}

/**
 * Hand `content` to the wizard.
 *
 * Idempotent, and that is the point: the wizard is a live form, and mounting a second one would
 * clear the inputs the owner is halfway through — on screen 3 those are a passphrase and two
 * words read off a sheet that is already printed.
 */
function showWizard(host: HTMLElement): void {
  if (disposeWizard) return;
  // The dashboard cannot be up at the same time, but a re-provision would reach here with one
  // mounted; tearing it down first keeps the two from painting over each other.
  dashboard?.destroy();
  dashboard = undefined;
  clear(host);
  disposeWizard = startWizard(host, window.bridge, {
    onDone: () => {
      // Clear the handle BEFORE routing. `decideContent` gives a live wizard priority over
      // everything, so leaving it set here would make completion the one transition that could
      // never happen — the wizard would sit on the done screen forever.
      disposeWizard?.();
      disposeWizard = undefined;
      void route();
    },
  });
}

/**
 * Hand `content` to the dashboard.
 *
 * Mounted once. `mountDashboard` owns its own refresh loop, status subscription, locale and
 * request sequencing, so re-mounting it on every route would throw away the company the owner
 * picked and re-run every IPC call for nothing.
 */
function showDashboard(host: HTMLElement): void {
  if (dashboard) return;
  clear(host);
  // The locked dashboard offers an Unlock button, and clicking it opens the passphrase prompt
  // below. Without this the owner reaches "enter your passphrase to see your figures" with no
  // field to type in — a dead end after setup, which is exactly where a real owner got stuck.
  dashboard = mountDashboard(host, { onUnlockRequested: () => promptUnlock(host) });
  void dashboard.refresh();
}

/** The current UI locale, read the same way `mountDashboard` reads it. */
function currentLocale(): Locale {
  try {
    const v = window.localStorage.getItem('tally-bridge.locale');
    return isLocale(v) ? v : 'en';
  } catch {
    return 'en';
  }
}

/**
 * The passphrase prompt: derive the key from the owner's passphrase and unlock the local
 * figures. The heavy lifting (Argon2id, the wrapped-blob unwrap, the roster) is the main
 * process's `unlock` IPC — this only collects the passphrase and reports success or a retry.
 *
 * The passphrase never leaves this function except through `window.bridge.unlock`, is masked in
 * the field, is scrubbed from the field after each attempt, and is never logged.
 */
function promptUnlock(host: HTMLElement): void {
  if (host.querySelector('.unlock-overlay')) return; // never stack two prompts
  const t = translator(currentLocale());

  const overlay = el('div', 'unlock-overlay');
  const card = el('div', 'unlock-card');
  const input = el('input', 'unlock-input');
  input.type = 'password';
  input.autocomplete = 'off';
  input.setAttribute('aria-label', t('unlock.title'));
  input.placeholder = t('unlock.placeholder');
  const error = el('p', 'unlock-error');
  const actions = el('div', 'unlock-actions');

  const close = () => {
    input.value = ''; // scrub
    if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
  };

  const submit = button('status-action primary', t('locked.action'), () => void attempt());
  const cancel = button('status-action', t('unlock.cancel'), close);

  async function attempt(): Promise<void> {
    const passphrase = input.value;
    if (!passphrase) {
      input.focus();
      return;
    }
    submit.disabled = true;
    cancel.disabled = true;
    error.textContent = '';
    submit.textContent = t('unlock.working');
    let ok = false;
    try {
      ok = await window.bridge.unlock(passphrase);
    } catch {
      ok = false;
    }
    input.value = ''; // scrub whatever the result
    submit.textContent = t('locked.action');
    submit.disabled = false;
    cancel.disabled = false;
    if (ok) {
      close();
      void dashboard?.refresh(); // now unlocked -> the cards render
    } else {
      error.textContent = t('unlock.wrong');
      input.focus();
    }
  }

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') void attempt();
    if (e.key === 'Escape') close();
  });

  mount(actions, cancel, submit);
  mount(card, el('h2', 'unlock-title', t('unlock.title')), el('p', 'unlock-sub', t('unlock.sub')), input, error, actions);
  mount(overlay, card);
  mount(host, overlay);
  input.focus();
}

function boot(): void {
  // If the preload never ran, `window.bridge` is undefined and every call below is a TypeError
  // that aborts boot() and leaves the "Starting Tally Bridge…" placeholder on screen forever.
  // Say so instead — this is a broken install, and it is the one thing an owner can report.
  if (!window.bridge) {
    clear(root);
    mount(root, renderEmpty('Tally Bridge did not load correctly. Please reinstall the app.'));
    return;
  }

  clear(root);
  content = document.createElement('div');
  mount(root, content);
  void route();
}

// A last-resort net. Nothing above should reach this — every bridge call goes through `ask` —
// but an unhandled rejection in a renderer is otherwise completely invisible.
window.addEventListener('unhandledrejection', (e) => {
  console.error('[bridge] unhandled rejection in renderer:', e.reason);
});

boot();
