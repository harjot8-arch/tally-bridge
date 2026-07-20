/**
 * The dashboard page. DOM glue only — every figure comes from the data layer
 * (./tally-data.js, built from apps/web/src/data) via the pure mapping in ./viewmap.js.
 *
 * Security contract (apps/web/README.md):
 *  - every decrypted string reaches the DOM through textContent, never as markup
 *    (party and company names are attacker-controlled: `A & B Traders <Mumbai>`);
 *  - UnlockError.message and result.message are shown verbatim;
 *  - the UnlockedSession is never logged, stored, or copied;
 *  - nothing is fetched from a third-party origin — no CDN, no fonts, no analytics.
 *
 * Animations are CSS transitions + the Web Animations API; the original design pulled GSAP
 * from a CDN, which the CSP (no remote origins) forbids.
 */
import {
  unlock,
  loadDashboard,
  lockSession,
  localStorageKV,
  memoryKV,
  workerUnlockSeams,
  UnlockError,
  formatMoney,
  formatDelta,
} from './tally-data.js';
import { mapCompany } from './viewmap.js';

const FMT = { formatMoney, formatDelta };
const $ = (id) => document.getElementById(id);
const finePointer = window.matchMedia('(pointer: fine)').matches;

const state = { session: null, companies: [], idx: 0 };

/* ------------------------------------------------------------------ cursor */

const cursor = $('cursor');
const follower = $('cursor-follower');
if (finePointer) {
  let cx = 0, cy = 0, fx = 0, fy = 0;
  document.addEventListener('mousemove', (e) => {
    cx = e.clientX; cy = e.clientY;
    cursor.style.transform = `translate3d(${cx}px, ${cy}px, 0) translate(-50%, -50%)`;
  }, { passive: true });
  const follow = () => {
    fx += (cx - fx) * 0.15; fy += (cy - fy) * 0.15;
    follower.style.transform = `translate3d(${fx}px, ${fy}px, 0) translate(-50%, -50%)`;
    requestAnimationFrame(follow);
  };
  requestAnimationFrame(follow);
}

const bindHover = () => {
  if (!finePointer) return;
  document.querySelectorAll('.hover-trigger, input, button').forEach((el) => {
    el.addEventListener('mouseenter', () => follower.classList.add('active'));
    el.addEventListener('mouseleave', () => follower.classList.remove('active'));
  });
};

/* ------------------------------------------------------------------ clock */

setInterval(() => {
  $('sys-clock').textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
}, 1000);

/* ------------------------------------------------------------------ unlock */

const STAGE_LABEL = {
  contacting: 'Contacting server…',
  deriving: 'Deriving key… (a few seconds)',
  'signing-in': 'Signing in…',
  'fetching-keys': 'Fetching keys…',
  opening: 'Opening identity… (a few seconds)',
  verifying: 'Verifying…',
};

function storageKV() {
  try {
    return localStorageKV(window.localStorage);
  } catch {
    return memoryKV();
  }
}

let busy = false;
$('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (busy) return; // no double-submit: two concurrent Argon2id runs help nobody
  busy = true;
  const btn = $('auth-btn');
  const err = $('auth-error');
  btn.disabled = true;
  err.textContent = '';

  const deps = { fetch: window.fetch.bind(window), storage: storageKV() };
  let worker = null;
  const fail = (message) => {
    err.textContent = message;
    btn.textContent = 'Initialize Synchronization';
    btn.disabled = false;
    busy = false;
  };

  try {
    worker = new Worker(new URL('./tally-worker.js', import.meta.url), { type: 'module' });
    const session = await unlock(
      { ...deps, ...workerUnlockSeams(worker), onStage: (s) => { btn.textContent = STAGE_LABEL[s] ?? s; } },
      $('tenant-id').value.trim(),
      $('passphrase').value,
    );
    btn.textContent = 'Loading figures…';
    const result = await loadDashboard(deps, session);
    if (result.state === 'error') {
      await lockSession(session);
      fail(result.message);
      return;
    }
    state.session = session;
    reveal(result, session);
  } catch (ex) {
    fail(ex instanceof UnlockError ? ex.message : 'Something went wrong. Please try again.');
  } finally {
    if (worker) worker.terminate();
  }
});

$('lock-btn').addEventListener('click', async () => {
  if (state.session) await lockSession(state.session);
  location.reload();
});

/* ------------------------------------------------------------------ reveal + render */

function reveal(result, session) {
  state.companies = result.state === 'ready' ? result.companies : [];

  const notes = [];
  if (result.state === 'empty') notes.push('No figures have synced yet. Open the desktop app.');
  if (result.state === 'ready') {
    if (result.incomplete) notes.push('Some figures could not be shown.');
    if (result.staleRefused > 0) notes.push('The server offered out-of-date figures; they were ignored.');
  }
  if (!session.persistentMemory) {
    notes.push('This browser is not saving safety records (private browsing?), so rollback protection lasts only for this session.');
  }
  $('banner').textContent = notes.join(' ');

  buildTimeline();

  $('auth-curtain').classList.add('away');
  $('dashboard-wrapper').classList.add('on');
  document.querySelectorAll('.anim-panel').forEach((el, i) => {
    el.animate(
      [{ transform: 'translateY(40px)', opacity: 0 }, { transform: 'translateY(0)', opacity: 1 }],
      { duration: 900, delay: 400 + i * 40, easing: 'cubic-bezier(0.19, 1, 0.22, 1)', fill: 'backwards' },
    );
  });

  render(0, true);
}

function buildTimeline() {
  const c = $('timeline-container');
  c.textContent = '';
  state.companies.forEach((co, i) => {
    const b = document.createElement('div');
    b.className = `year-btn hover-trigger${i === state.idx ? ' active' : ''}`;
    b.textContent = co.name; // attacker-controlled string: textContent only
    magnetic(b);
    b.addEventListener('click', () => {
      if (i === state.idx) return;
      document.querySelectorAll('.year-btn').forEach((el) => el.classList.remove('active'));
      b.classList.add('active');
      render(i, false);
    });
    c.appendChild(b);
  });
  bindHover();
}

function magnetic(el) {
  if (!finePointer) return;
  el.addEventListener('mousemove', (e) => {
    const r = el.getBoundingClientRect();
    el.style.transition = 'color 0.3s';
    el.style.transform =
      `translate(${(e.clientX - r.left - r.width / 2) * 0.2}px, ${(e.clientY - r.top - r.height / 2) * 0.2}px)`;
  }, { passive: true });
  el.addEventListener('mouseleave', () => {
    el.style.transition = 'color 0.3s, transform 0.5s cubic-bezier(0.22, 1, 0.36, 1)';
    el.style.transform = '';
  });
}

function render(idx, first) {
  state.idx = idx;
  const cards = state.companies[idx];
  const view = mapCompany(cards ?? {}, FMT);
  $('as-of').textContent = cards ? `As of ${cards.asOf}` : '';
  paint(view, first);
}

function paint(view, first) {
  // Rows/cells whose data does not exist are hidden outright; a '—' value stays visible, dimmed.
  document.querySelectorAll('[data-slot]').forEach((slot) => {
    const probe = slot.querySelector('.ds-val');
    const v = probe ? view.text[probe.getAttribute('data-key')] : undefined;
    slot.style.display = v === '' || v === undefined ? 'none' : '';
  });

  document.querySelectorAll('.ds-val').forEach((el) => {
    const v = view.text[el.getAttribute('data-key')];
    el.textContent = v === undefined || v === '' ? '—' : v; // textContent only: v may be attacker-controlled
    el.classList.toggle('dim', el.textContent === '—');
    if (!first) {
      el.animate(
        [{ opacity: 0, transform: 'translateY(8px)' }, { opacity: 1, transform: 'none' }],
        { duration: 350, easing: 'ease-out' },
      );
    }
  });

  document.querySelectorAll('.ds-w').forEach((el) => {
    el.style.width = `${view.widths[el.getAttribute('data-key')] ?? 0}%`;
  });
  document.querySelectorAll('.ds-s').forEach((el) => {
    el.style.transform = `scaleX(${(view.scales[el.getAttribute('data-key')] ?? 0) / 100})`;
  });

  drawChart(view.chart, first);
}

function drawChart(values, first) {
  const path = document.querySelector('.chart-path');
  const area = document.querySelector('.chart-area');
  // COLLAPSE the chart, don't just blank it. Clearing `d` left the <svg> at its full
  // clamp(80px,15vw,120px) height, so a company whose sales have not synced yet showed ~120px of
  // pure void under a lone em-dash — the first visual pass at 390px read as a broken app rather
  // than one still syncing. Sections sync independently, so cash-only is a NORMAL first state.
  path.parentElement?.closest('.svg-chart')?.style.setProperty('display', values && values.length >= 2 ? '' : 'none');
  if (!values || values.length < 2) {
    path.removeAttribute('d');
    area.removeAttribute('d');
    return;
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const ys = values.map((v) => (92 - ((v - min) / span) * 72).toFixed(2));
  const step = 1000 / (values.length - 1);
  let d = `M 0 ${ys[0]}`;
  for (let i = 1; i < ys.length; i++) {
    const x0 = (i - 1) * step;
    d += ` C ${(x0 + step / 2).toFixed(1)} ${ys[i - 1]}, ${(x0 + step / 2).toFixed(1)} ${ys[i]}, ${(i * step).toFixed(1)} ${ys[i]}`;
  }
  path.setAttribute('d', d);
  area.setAttribute('d', `${d} L 1000 100 L 0 100 Z`);
  if (first) {
    const len = path.getTotalLength();
    path.animate(
      [{ strokeDasharray: len, strokeDashoffset: len }, { strokeDasharray: len, strokeDashoffset: 0 }],
      { duration: 1500, delay: 500, easing: 'ease-in-out', fill: 'backwards' },
    );
    area.animate([{ opacity: 0 }, { opacity: 0.12 }], { duration: 1000, delay: 1000, fill: 'backwards' });
  }
}

bindHover();
