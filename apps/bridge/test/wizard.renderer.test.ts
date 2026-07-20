import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LOCALES, LOCALE_NAMES } from '../src/renderer/i18n.ts';
import { makeRecoverySheet, type RecoverySheet } from '../src/onboarding/recovery.ts';
import type { ProvisionStep } from '../src/onboarding/vercel.ts';
import {
  initialState,
  next,
  type TallyCompany,
  type WizardEvent,
  type WizardState,
} from '../src/onboarding/wizard.ts';
import {
  LANGS,
  LANG_NAMES,
  PRO_PLAN_USD,
  STRINGS,
  actionLabel,
  describeWizard,
  isQrDataUrl,
  isWizardComplete,
  pickLang,
  progressPercent,
  proPlanRupees,
  rememberLang,
  decideContent,
  shouldShowWizard,
  storedLang,
  t,
  type Intent,
  type ScreenModel,
} from '../src/renderer/wizard.ts';

/**
 * Renderer wizard tests.
 *
 * There is no DOM here and there is no jsdom in this repo, which is a constraint that made the
 * design better rather than worse: everything worth asserting about this screen is a DECISION,
 * and every decision lives in `describeWizard` — a pure `WizardState -> ScreenModel` function
 * with no `document` in it. The DOM layer underneath is `appendChild` and `textContent` and
 * decides nothing.
 *
 * The states below are driven through the REAL machine (`src/onboarding/wizard.ts`) rather than
 * hand-written as object literals. A literal is a guess about what the machine produces, and a
 * guess drifts silently — these tests would keep passing against a screen that no longer exists.
 */

const ACME: TallyCompany = { guid: 'guid-acme', name: 'Acme Traders' };
const BETA: TallyCompany = { guid: 'guid-beta', name: 'Beta Exports' };
const PASS = 'ledger book monday';

function sheetFor(seed = 7): RecoverySheet {
  return makeRecoverySheet(new Uint8Array(32).fill(seed), 'Acme Traders', '2026-07-16');
}

function drive(events: WizardEvent[], from: WizardState = initialState()): WizardState {
  return events.reduce(next, from);
}

const atAwaitToken = (): WizardState =>
  drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
  ]);

const atProvisioning = (): WizardState =>
  drive([{ type: 'token_pasted', token: 'vercel_pat_x' }], atAwaitToken());

const atEntry = (): WizardState =>
  drive(
    [{ type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' }],
    atProvisioning(),
  );

const atSheet = (sheet: RecoverySheet = sheetFor()): WizardState =>
  drive(
    [
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'sheet_ready', sheet },
    ],
    atEntry(),
  );

const atVerify = (sheet: RecoverySheet = sheetFor()): WizardState =>
  drive([{ type: 'continue' }], atSheet(sheet));

// ---------------------------------------------------------------- language

test('EVERY string exists in EVERY language — a missing key is a blank label on a live screen', () => {
  const keys = Object.keys(STRINGS.en) as Array<keyof typeof STRINGS.en>;
  assert.ok(keys.length > 40, 'the dictionary should be substantial');

  for (const lang of LANGS) {
    for (const key of keys) {
      const s = STRINGS[lang][key];
      assert.equal(typeof s, 'string', `${lang}.${key} is missing`);
      assert.ok(s.trim().length > 0, `${lang}.${key} is blank`);
    }
  }
});

test('Hindi is actually translated, not English wearing a label', () => {
  const keys = Object.keys(STRINGS.en) as Array<keyof typeof STRINGS.en>;
  // Product names (Tally, Vercel) legitimately survive translation, so this is a corpus-level
  // check rather than a per-key one: if someone stubs the Hindi dictionary by copying English,
  // this goes red.
  const same = keys.filter((k) => STRINGS.hi[k] === STRINGS.en[k]);
  assert.ok(same.length <= 2, `Hindi looks copied from English for: ${same.join(', ')}`);

  // Devanagari, not transliteration.
  for (const key of ['s1_wait_not_running', 's3_only_key_body', 'done_title'] as const) {
    assert.match(STRINGS.hi[key], /[ऀ-ॿ]/, `${key} is not in Devanagari`);
  }
});

test('t() substitutes named variables and leaves unknown ones alone rather than blanking them', () => {
  assert.equal(t('en', 'step_of', { n: '2' }), 'Step 2 of 3');
  assert.match(t('hi', 'step_of', { n: '2' }), /2/);
  // A missing var must not silently produce "Step  of 3" — a visible {n} is a bug report.
  assert.match(t('en', 'step_of', {}), /\{n\}/);
});

test('THE LANGUAGE SEAM: the wizard and the dashboard share one locale vocabulary', () => {
  // The wizard is where the language is CHOSEN — it runs before the dashboard exists. If the two
  // surfaces each had their own notion of "language", an owner would pick हिंदी during setup and
  // land on an English dashboard thirty seconds later, which reads as the setting not working.
  assert.deepEqual([...LANGS], [...LOCALES]);
  assert.deepEqual(LANG_NAMES, LOCALE_NAMES);
});

test('the locale storage key does not drift from the dashboard that reads it', () => {
  // `dashboard.ts` owns this key and does not export it, so the wizard carries a copy. A copy
  // agrees with the original only until someone edits one of them — and the symptom would be
  // silent: setup's language choice simply ignored, with nothing failing anywhere. So the
  // duplication is checked over the SOURCE, which is the only thing that can see it.
  const read = (f: string) => readFileSync(join(import.meta.dirname, '../src/renderer', f), 'utf8');

  const keyIn = (src: string, file: string): string => {
    const m = /'(tally-bridge\.[a-z]+)'/.exec(src);
    assert.ok(m, `${file} no longer names a tally-bridge storage key — did it move?`);
    return m[1]!;
  };

  assert.equal(
    keyIn(read('wizard.ts'), 'wizard.ts'),
    keyIn(read('dashboard.ts'), 'dashboard.ts'),
    'the wizard writes the language somewhere the dashboard does not read',
  );
});

test('the wizard remembers the language for the dashboard, and survives storage being off', () => {
  const store = new Map<string, string>();
  const original = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');

  const install = (impl: object | undefined) =>
    Object.defineProperty(globalThis, 'localStorage', { value: impl, configurable: true });

  try {
    install({
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    });

    assert.equal(storedLang(), undefined, 'nothing chosen yet');
    rememberLang('hi');
    assert.equal(storedLang(), 'hi');

    // A junk value in the drawer must not become a locale. `isLocale` is the gate.
    store.set('tally-bridge.locale', 'kl');
    assert.equal(storedLang(), undefined);

    // Storage THROWS rather than returning null when it is disabled by policy — a language
    // preference is not worth a broken setup screen.
    install({
      getItem: () => {
        throw new Error('storage disabled');
      },
      setItem: () => {
        throw new Error('storage disabled');
      },
    });
    assert.equal(storedLang(), undefined);
    assert.doesNotThrow(() => rememberLang('hi'));
  } finally {
    if (original) Object.defineProperty(globalThis, 'localStorage', original);
    else Reflect.deleteProperty(globalThis, 'localStorage');
  }
});

test('pickLang reads the platform tag, and anything unknown lands on English', () => {
  assert.equal(pickLang('hi'), 'hi');
  assert.equal(pickLang('hi-IN'), 'hi');
  assert.equal(pickLang('HI-in'), 'hi');
  assert.equal(pickLang('en-IN'), 'en');
  assert.equal(pickLang('ta-IN'), 'en');
  assert.equal(pickLang(undefined), 'en');
  assert.equal(pickLang(''), 'en');
});

test('NO ENGLISH IN LOGIC: the screen is chosen by discriminants, never by matching prose', () => {
  // The proof: the machine's own message is English, but the first screen's sentence changes
  // with the language — so it cannot have come from reading `state.message`.
  const notRunning = next(initialState(), { type: 'probe_failed', failure: { kind: 'not_running' } });

  const en = describeWizard(notRunning, 'en');
  const hi = describeWizard(notRunning, 'hi');

  assert.deepEqual(en.body, [STRINGS.en.s1_wait_not_running, STRINGS.en.s1_wait_calm]);
  assert.deepEqual(hi.body, [STRINGS.hi.s1_wait_not_running, STRINGS.hi.s1_wait_calm]);
  assert.notDeepEqual(en.body, hi.body);

  // Same for the other wait reason, which differs ONLY by its discriminant.
  const noCompany = next(initialState(), { type: 'probe_failed', failure: { kind: 'no_company_open' } });
  assert.equal(describeWizard(noCompany, 'hi').body[0], STRINGS.hi.s1_wait_no_company);
});

test('every ActionKind the machine can emit has a label in every language', () => {
  // ActionKind is a closed union, so the renderer can translate a button without reading the
  // English label that rides along with it. If a kind is added and not translated, the fallback
  // is the machine's English — a real sentence, never a blank button — but this test names it.
  const kinds = [
    'retry_probe',
    'open_neon',
    'paste_new_token',
    'open_vercel_billing',
    'choose_another_name',
    'retry_provision',
    'choose_another_passphrase',
    'print_again',
    'start_again',
  ] as const;

  for (const lang of LANGS) {
    for (const kind of kinds) {
      const label = actionLabel(lang, kind, 'FALLBACK');
      assert.notEqual(label, 'FALLBACK', `${lang}: ${kind} has no translated label`);
      assert.ok(label.length > 0);
    }
  }

  // An unknown kind degrades to the machine's own label rather than to nothing.
  assert.equal(actionLabel('hi', 'not_a_real_kind' as never, 'Try again'), 'Try again');
});

// ---------------------------------------------------------------- screen 1

test('SCREEN 1: Tally closed is calm — waiting tone, one sentence, one button, no error code', () => {
  const s = next(initialState(), { type: 'probe_failed', failure: { kind: 'not_running' } });

  for (const lang of LANGS) {
    const m = describeWizard(s, lang);
    assert.equal(m.step, 1);
    // NOT 'problem'. Tally is closed every night and every weekend; rendering that red trains an
    // owner to ignore red, which costs you the one time it is real.
    assert.equal(m.tone, 'waiting');
    assert.ok(m.action, 'a wait must still offer a way forward');
    assert.equal(m.action.intent.kind, 'retry');

    // No error code can hide in a string with no digits in it.
    for (const line of m.body) assert.equal(/\d/.test(line), false, `digits in: ${line}`);
  }
});

test('SCREEN 1: one company is pre-selected and Continue is live; several force a choice', () => {
  const one = describeWizard(next(initialState(), { type: 'probe_succeeded', companies: [ACME] }), 'en');
  assert.equal(one.companies.length, 1);
  assert.equal(one.companies[0]!.selected, true);
  assert.ok(one.primary, 'a single company should be one click from Continue');

  const many = describeWizard(next(initialState(), { type: 'probe_succeeded', companies: [ACME, BETA] }), 'en');
  assert.equal(many.companies.filter((c) => c.selected).length, 0);
  // No live button that does nothing. The GUID is the identity; guessing it is how a year of
  // data ends up under the wrong company.
  assert.equal(many.primary, undefined, 'Continue must not appear before a company is chosen');

  const picked = drive(
    [{ type: 'probe_succeeded', companies: [ACME, BETA] }, { type: 'select_company', guid: BETA.guid }],
  );
  const after = describeWizard(picked, 'en');
  assert.ok(after.primary);
  assert.equal(after.companies.find((c) => c.selected)?.guid, BETA.guid);
});

test('SCREEN 1: a company name is carried as data, never interpreted', () => {
  // A supplier can legitimately name themselves this, and the string comes straight out of a
  // customer's Tally file. It reaches the model verbatim; the DOM layer sets it with
  // textContent, which is the whole defence.
  const nasty: TallyCompany = { guid: 'g', name: '<img src=x onerror=alert(1)> & Sons' };
  const m = describeWizard(next(initialState(), { type: 'probe_succeeded', companies: [nasty] }), 'en');
  assert.equal(m.companies[0]!.name, nasty.name);
});

// ---------------------------------------------------------------- screen 2

test('SCREEN 2: THE COST CONVERSATION happens before setup, not after suspension', () => {
  // Vercel Hobby is non-commercial. A business on it is in breach and is suspendable, and the
  // way that surfaces is an angry call after the dashboard has gone dark.
  for (const lang of LANGS) {
    const m = describeWizard(atAwaitToken(), lang);
    const cost = m.notes.find((n) => n.title === STRINGS[lang].s2_cost_title);
    assert.ok(cost, `${lang}: the cost note is missing from the token screen`);
    assert.equal(cost.weight, 'hard');
    assert.match(cost.body, /20/, 'the actual USD price must be on screen');
    assert.ok(cost.body.includes(proPlanRupees()), 'the rupee figure must be on screen');
  }

  // And it is up before the owner has spent a minute — on the very first cloud phase too.
  assert.ok(describeWizard(drive([{ type: 'probe_succeeded', companies: [ACME] }, { type: 'continue' }]), 'en').notes.length > 0);
});

test('INDIAN NUMBERING: money is grouped by lakh, never by thousand', () => {
  const inr = proPlanRupees();
  assert.match(inr, /^₹[\d,]+$/);
  // The rate is approximate by design, but the price must stay in the right order of magnitude:
  // a rate typo that renders ₹176 or ₹17,600 is a different sales conversation.
  const digits = Number(inr.replace(/[₹,]/g, ''));
  assert.ok(digits >= 1000 && digits <= 3000, `implausible rupee price: ${inr}`);
  assert.equal(PRO_PLAN_USD, 20);
  // Round hundreds only — a number claiming precision it cannot have invites being held to it.
  assert.equal(digits % 100, 0);
});

test('SCREEN 2: THE VERCEL PASTE is offered with the page, not demanded from memory', () => {
  const m = describeWizard(atAwaitToken(), 'en');
  assert.deepEqual(m.fields.map((f) => f.id), ['token']);
  assert.equal(m.fields[0]!.kind, 'token');
  assert.ok(m.primary, 'there must be a way to submit the paste');
  assert.equal(m.primary.intent.kind, 'submit_token');
  // We open the page for them; they do not go hunting for it.
  assert.ok(m.action);
  assert.equal(m.action.intent.kind, 'open');
  assert.match(m.action.url!, /^https:\/\/vercel\.com\//);
  assert.equal(m.tone, 'calm', 'a step we cannot automate is not the owner doing something wrong');
});

test('SCREEN 2: THE ONE NEON CLICK is guided and calm, and the bar keeps moving', () => {
  const s = next(atProvisioning(), {
    type: 'provision_event',
    event: {
      kind: 'needs_human',
      action: 'install_neon',
      url: 'https://vercel.com/marketplace/neon',
      message: 'Click "Install" on the Neon page, then come back here.',
    },
  });
  const m = describeWizard(s, 'en');

  // Nobody did anything wrong: Vercel has NO REST endpoint for marketplace terms.
  assert.equal(m.tone, 'calm');
  assert.ok(m.action);
  assert.equal(m.action.intent.kind, 'open');
  assert.equal(m.action.url, 'https://vercel.com/marketplace/neon');
  // The bar stays on screen while we poll, so the owner comes back to a page that is visibly
  // still working rather than one that looks stalled.
  assert.ok(m.progress, 'the progress bar must survive the manual click');
  assert.equal(m.progress.label, STRINGS.en.s2_neon_waiting);
});

test('SCREEN 2: ONE progress bar, carrying the provisioner\'s own sentence — never a step name', () => {
  const s = next(atProvisioning(), {
    type: 'provision_event',
    event: { kind: 'step', step: 'provision_database', message: 'Creating your database…' },
  });
  const m = describeWizard(s, 'en');
  assert.ok(m.progress);
  assert.equal(m.progress.label, 'Creating your database…');
  // `provision_database` is our vocabulary. It must never reach the screen.
  assert.equal(/provision_database|_/.test(m.progress.label), false);
  assert.ok(m.progress.percent > 0 && m.progress.percent < 100);
});

test('the progress bar only ever moves forward, and only "done" is 100%', () => {
  const order: ProvisionStep[] = [
    'verify_token', 'resolve_team', 'check_neon', 'await_neon_install', 'create_project',
    'provision_database', 'connect_database', 'set_env', 'upload_files', 'deploy',
    'await_ready', 'done',
  ];
  let last = -1;
  for (const step of order) {
    const p = progressPercent(step);
    assert.ok(p > last, `${step} went backwards (${p} after ${last})`);
    assert.ok(p >= 0 && p <= 100);
    last = p;
  }
  assert.equal(progressPercent('done'), 100);
  // An unknown step reads as "just started", never as finished. A bar that claims 100% while
  // the app is still working is the one lie a progress bar can tell.
  assert.equal(progressPercent('some_new_step' as ProvisionStep), 0);
});

test('SCREEN 2: a real failure is a problem with exactly one action, and no jargon', () => {
  const s = next(atProvisioning(), {
    type: 'provision_failed',
    error: new TypeError("Cannot read properties of undefined (reading 'store')"),
  });
  const m = describeWizard(s, 'en');
  assert.equal(m.tone, 'problem');
  assert.ok(m.action);
  assert.equal(m.primary, undefined, 'a failure offers ONE action, never a menu');
  for (const line of m.body) {
    assert.equal(/TypeError|undefined|\.ts:|\bat \w+\(/.test(line), false, `raw error in: ${line}`);
  }
});

// ---------------------------------------------------------------- screen 3

test('SCREEN 3: the no-reset consequence and the floor under it ALWAYS travel together', () => {
  // Vivid, then calm. An owner told only "there is no reset" abandons setup. An owner told only
  // "your figures are safe" never prints the sheet. Both, in this order, or neither.
  for (const lang of LANGS) {
    const m = describeWizard(atEntry(), lang);

    const hard = m.notes.filter((n) => n.weight === 'hard');
    const soft = m.notes.filter((n) => n.weight === 'soft');
    assert.equal(hard.length, 1, `${lang}: the consequence must be stated exactly once`);
    assert.equal(soft.length, 1, `${lang}: the consequence must never stand alone`);

    // Order is the message. The reassurance comes second, or it reads as an excuse for the first.
    assert.ok(m.notes.indexOf(hard[0]!) < m.notes.indexOf(soft[0]!), `${lang}: notes are out of order`);

    assert.equal(hard[0]!.body, STRINGS[lang].s3_only_key_body);
    assert.equal(soft[0]!.body, STRINGS[lang].s3_forget_body);
  }

  // The hard note does not hedge: no reset, no copy — that is the product, stated plainly.
  assert.match(STRINGS.en.s3_only_key_body, /cannot reset it/i);
  assert.match(STRINGS.en.s3_only_key_body, /do not keep a copy/i);
  // And the floor is the architectural fact, not a comfort: Tally is the source of truth, the
  // server is a derivative cache, so total key loss is a re-sync.
  assert.match(STRINGS.en.s3_forget_body, /Tally is the real record/i);
});

test('SCREEN 3: the passphrase and its confirmation are the only fields, and both are masked', () => {
  const m = describeWizard(atEntry(), 'en');
  assert.deepEqual(m.fields.map((f) => f.id), ['passphrase', 'confirm']);
  for (const f of m.fields) assert.equal(f.kind, 'secret');
  assert.equal(m.primary!.intent.kind, 'submit_passphrase');
});

test('SCREEN 3: the sheet shows the QR first and all 24 words, and never prints the raw key', () => {
  const sheet = sheetFor();
  const m = describeWizard(atSheet(sheet), 'en', 'data:image/png;base64,AAAA');

  assert.ok(m.sheet);
  assert.equal(m.sheet.sheet.words.length, 24);
  assert.equal(m.sheet.qrDataUrl, 'data:image/png;base64,AAAA');

  // The base64 key is what the QR encodes; it must not be sitting on screen as text for a
  // shoulder to read or a screenshot to catch.
  const onScreen = [...m.body, m.title, ...m.notes.map((n) => n.body)].join(' ');
  assert.equal(onScreen.includes(sheet.keyBase64), false, 'the raw recovery key must not be rendered');

  // Business name and date are printed so a drawer full of these can be ordered.
  assert.ok(m.body.some((b) => b.includes('Acme Traders') && b.includes('2026-07-16')));
});

test('THE QR GATE: only a raster image data URL may reach an img src', () => {
  // `src` is a URL context, not a text context — textContent discipline does not reach it and
  // escaping would not either. This codebase has already had an injection through exactly here.
  assert.equal(isQrDataUrl('data:image/png;base64,iVBORw0KGgo='), true);
  assert.equal(isQrDataUrl('data:image/jpeg;base64,AAAA'), true);
  assert.equal(isQrDataUrl('data:image/webp;base64,AA=='), true);

  for (const bad of [
    'javascript:alert(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'data:image/png;base64,AAA" onerror="alert(1)',
    'data:image/png;base64,AAA><script>alert(1)</script>',
    // SVG is a DOCUMENT. recovery.ts allows it for printToPDF in a throwaway process; this page
    // holds the bridge, and a QR is raster — nothing legitimate is lost by refusing it here.
    'data:image/svg+xml;base64,PHN2Zy8+',
    'https://example.com/qr.png',
    'file:///etc/passwd',
    '',
    ' data:image/png;base64,AAAA',
  ]) {
    assert.equal(isQrDataUrl(bad), false, `must reject: ${bad}`);
  }
});

test('SCREEN 3: "I have printed it" leads to the CHECK, never past it', () => {
  const m = describeWizard(atSheet(), 'en');
  assert.equal(m.primary!.intent.kind, 'continue');
  // And the machine takes `continue` from `sheet` to `verify` — not to done.
  const after = next(atSheet(), { type: 'continue' });
  assert.equal(after.screen, 'setPassphrase');
  assert.equal(after.screen === 'setPassphrase' ? after.phase : '', 'verify');
});

// ---------------------------------------------------------------- THE GATE

test('THE GATE: the verify screen asks for words #4 and #17, as printed on the sheet', () => {
  const m = describeWizard(atVerify(), 'en');
  assert.deepEqual(m.fields.map((f) => f.id), ['word-4', 'word-17']);
  assert.deepEqual(m.fields.map((f) => f.kind), ['word', 'word']);
  // The label carries the number the owner reads off the paper.
  assert.match(m.fields[0]!.label, /4/);
  assert.match(m.fields[1]!.label, /17/);
});

test('THE GATE IS UNSKIPPABLE: no model the renderer can produce offers a way around it', () => {
  // The hole this guards is the one that already existed once: a gate living in a click handler
  // is one `if` away from a "Skip for now" forever. Here the gate is in the machine, and the
  // renderer's job is to have NO intent that could bypass it.
  //
  // `Intent` is a closed union with no `skip` member, so this checks the reachable surface: for
  // every state on the way to done, no offered intent advances anything by itself.
  const sheet = sheetFor();
  const models: ScreenModel[] = [
    describeWizard(atSheet(sheet), 'en'),
    describeWizard(atVerify(sheet), 'en'),
    describeWizard(next(atVerify(sheet), { type: 'verify_submitted', answers: ['no', 'no'] }), 'en'),
  ];

  for (const m of models) {
    assert.equal(m.complete, false, 'nothing before done may claim completion');
    const intents: Intent[] = [m.primary?.intent, m.action?.intent].filter((i): i is Intent => !!i);
    assert.ok(intents.length > 0, 'every screen must offer something');
    for (const i of intents) {
      // Every intent is either inert (open/print), sends a machine event, or is `continue` —
      // and `continue` at the gate is a no-op in the machine, verified below.
      assert.ok(
        ['continue', 'retry', 'open', 'print', 'submit_verify', 'select_company'].includes(i.kind),
        `unexpected escape hatch: ${i.kind}`,
      );
    }
  }

  // The verify screen offers exactly one forward move, and it is the submission itself.
  const verify = describeWizard(atVerify(sheet), 'en');
  assert.equal(verify.primary!.intent.kind, 'submit_verify');
  // No second button to walk past the check with.
  assert.equal(verify.action, undefined);

  // And `continue` — the intent every other screen uses to advance — cannot open the gate.
  assert.equal(isWizardComplete(next(atVerify(sheet), { type: 'continue' })), false);
});

test('THE GATE: only the machine can produce done, and only from the right two words', () => {
  const sheet = sheetFor();
  const verify = atVerify(sheet);

  assert.equal(isWizardComplete(verify), false);
  assert.equal(isWizardComplete(next(verify, { type: 'verify_submitted', answers: ['x', 'y'] })), false);
  assert.equal(isWizardComplete(next(verify, { type: 'verify_submitted', answers: [] })), false);

  const done = next(verify, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  assert.equal(isWizardComplete(done), true);
  assert.equal(describeWizard(done, 'en').complete, true);
});

test('isWizardComplete FAILS CLOSED: `undefined === undefined` must never open a gate', () => {
  // The original bug in this product, in its general form: a state that had not loaded compared
  // equal to a state that had, and the one gate that must not be walked past was walked past by
  // an IPC call that simply had not resolved yet.
  for (const notDone of [
    undefined,
    null,
    {},
    { screen: undefined },
    { screen: null },
    { screen: 'Done' },
    { screen: 'done ' },
    { phase: 'done' },
    'done',
    0,
    NaN,
    [],
    { screen: { toString: () => 'done' } },
  ]) {
    assert.equal(isWizardComplete(notDone), false, `${JSON.stringify(notDone)} must not read as done`);
  }
  assert.equal(isWizardComplete({ screen: 'done' }), true);
});

test('shouldShowWizard FAILS CLOSED: anything but a hard true means set up', () => {
  // `isProvisioned` can REJECT, and the caller's fallback for a rejected call is not a fact. An
  // empty dashboard implies "you have no data"; the setup screen implies "finish setting up".
  // Only the second is safe to be wrong about.
  assert.equal(shouldShowWizard(true), false);
  for (const v of [false, undefined, null, 0, '', 'true', 1, {}, []]) {
    assert.equal(shouldShowWizard(v), true, `${JSON.stringify(v)} must not skip setup`);
  }
});

// ---------------------------------------------------------------- global properties

/** Every state the model can be asked to render, driven through the real machine. */
function reachableStates(): WizardState[] {
  const sheet = sheetFor();
  const out: WizardState[] = [initialState()];

  for (const f of [
    { kind: 'not_running' },
    { kind: 'no_company_open' },
    { kind: 'not_tally', bodyExcerpt: '<html>' },
    { kind: 'tally_error', message: 'Licence not active' },
    { kind: 'timeout', afterMs: 10_000 },
    { kind: 'http_status', status: 502 },
    { kind: 'network', message: 'ECONNREFUSED' },
  ] as const) {
    out.push(next(initialState(), { type: 'probe_failed', failure: f }));
  }

  out.push(next(initialState(), { type: 'probe_succeeded', companies: [ACME] }));
  out.push(next(initialState(), { type: 'probe_succeeded', companies: [ACME, BETA] }));
  out.push(drive([{ type: 'probe_succeeded', companies: [ACME] }, { type: 'continue' }]));
  out.push(atAwaitToken(), atProvisioning());

  for (const step of ['create_project', 'deploy', 'await_ready'] as ProvisionStep[]) {
    out.push(next(atProvisioning(), { type: 'provision_event', event: { kind: 'step', step, message: 'Working…' } }));
  }
  out.push(
    next(atProvisioning(), {
      type: 'provision_event',
      event: { kind: 'needs_human', action: 'install_neon', url: 'https://vercel.com/marketplace/neon', message: 'Click Install.' },
    }),
  );
  out.push(next(atProvisioning(), { type: 'provision_failed', error: new Error('x') }));

  out.push(atEntry());
  out.push(next(atEntry(), { type: 'passphrase_submitted', passphrase: 'short', confirm: 'short' }));
  out.push(next(atEntry(), { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS }));
  out.push(atSheet(sheet));
  out.push(next(atSheet(sheet), { type: 'print_failed', error: new Error('ENOENT') }));
  out.push(atVerify(sheet));
  out.push(next(atVerify(sheet), { type: 'verify_submitted', answers: ['no', 'no'] }));
  out.push(next(atVerify(sheet), { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] }));

  return out;
}

test('describeWizard is TOTAL: every reachable state renders a titled screen in every language', () => {
  // A phase the model forgot would otherwise render as an empty card — a dead end with no title,
  // no text and no button, on the screen that decides whether this product is usable at all.
  for (const s of reachableStates()) {
    for (const lang of LANGS) {
      const m = describeWizard(s, lang);
      assert.ok(m.title.length > 0, `${s.screen}/${'phase' in s ? s.phase : ''} has no title`);
      assert.ok([1, 2, 3].includes(m.step));
      assert.ok(m.stepOf.length > 0);
      assert.ok(
        m.primary || m.action || m.progress || m.body.length > 0,
        `${s.screen} is a dead end in ${lang}`,
      );
    }
  }
});

test('EVERY screen is a sentence and a way forward — never a code, never a dead end', () => {
  const banned: Array<[RegExp, string]> = [
    [/\bat [A-Za-z$_][\w.$]*\s*\(/, 'a stack frame'],
    [/\.ts:\d+|\.js:\d+/, 'a source location'],
    [/TypeError|ReferenceError|SyntaxError/, 'an exception class'],
    [/ECONNREFUSED|ENOENT|EADDRINUSE/, 'an errno'],
    [/\bHTTP \d|\bstatus \d/i, 'a status code'],
    [/\n/, 'a multi-line dump'],
  ];

  for (const s of reachableStates()) {
    for (const lang of LANGS) {
      const m = describeWizard(s, lang);
      const prose = [m.title, ...m.body, ...m.notes.map((n) => `${n.title} ${n.body}`)];
      for (const line of prose) {
        for (const [re, what] of banned) {
          assert.equal(re.test(line), false, `${s.screen} shows ${what}: ${JSON.stringify(line)}`);
        }
      }
      // A failure gets exactly ONE action. An owner staring at two buttons at the moment
      // something broke picks neither and phones you.
      if (m.tone === 'problem') {
        assert.ok(m.action, `${s.screen} failed with no way forward`);
        assert.equal(m.primary, undefined, `${s.screen} offers a menu at the moment of failure`);
      }
    }
  }
});

test('a URL only ever reaches a button as https, on the allowlisted hosts', () => {
  // `openExternal` runs whatever protocol handler the URL names. Main validates against
  // `safeExternalUrl`, and this asserts the renderer never even tries anything else.
  for (const s of reachableStates()) {
    const m = describeWizard(s, 'en');
    for (const i of [m.primary?.intent, m.action?.intent]) {
      if (i?.kind !== 'open') continue;
      assert.match(i.url, /^https:\/\//, `not https: ${i.url}`);
      const host = new URL(i.url).hostname;
      assert.ok(
        host === 'vercel.com' || host.endsWith('.vercel.com') || host === 'neon.tech',
        `off-allowlist host: ${host}`,
      );
    }
  }
});

test('describeWizard is pure: rendering a screen never mutates the state it was handed', () => {
  for (const s of reachableStates()) {
    const snapshot = structuredClone(s);
    describeWizard(s, 'en');
    describeWizard(s, 'hi');
    assert.deepEqual(s, snapshot);
  }
});

test('THE FULL WALK: the happy path renders three steps and reaches done only at the gate', () => {
  const sheet = sheetFor();
  const seen: Array<{ step: number; complete: boolean }> = [];
  const record = (s: WizardState) => {
    const m = describeWizard(s, 'hi');
    seen.push({ step: m.step, complete: m.complete });
    return s;
  };

  const events: WizardEvent[] = [
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_event', event: { kind: 'needs_human', action: 'install_neon', url: 'https://vercel.com/marketplace/neon', message: 'Click Install.' } },
    { type: 'provision_event', event: { kind: 'step', step: 'deploy', message: 'Deploying…' } },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
    { type: 'printed' },
    { type: 'continue' },
  ];

  let s = record(initialState());
  for (const e of events) s = record(next(s, e));

  // Not once before the final answer.
  assert.equal(seen.some((x) => x.complete), false, 'a screen claimed completion before the gate');
  assert.deepEqual([...new Set(seen.map((x) => x.step))], [1, 2, 3], 'the walk must cross three steps');

  s = record(next(s, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] }));
  assert.equal(seen.at(-1)!.complete, true);
});

// ---------------------------------------------------------------- who owns the screen

/**
 * `decideContent` — the rule that keeps the recovery sheet on screen.
 *
 * THE BUG THIS PINS IS A SILENT, PERMANENT LOSS OF THE RECOVERY KEY:
 *
 *   `isProvisioned()` reports what the KEYSTORE holds, and the keystore is written during the
 *   WRAP — after the passphrase is submitted, two screens before the wizard finishes. The old
 *   shell asked that flag whether SETUP WAS DONE, saw `true` while the owner was still looking
 *   at their recovery sheet, and disposed the wizard. The flag stays true forever, so the wizard
 *   never returned. `completeSetup` mints that key exactly once: it was gone, unverified.
 *
 * So the rule is about AUTHORITY, and the tests below are about the order of the two checks: a
 * live wizard outranks the flag unconditionally, including when the flag cannot be read.
 */
test('A LIVE WIZARD OUTRANKS A TRUE isProvisioned — this is what saves the recovery sheet', () => {
  // The exact state during the sheet and verify screens: the keystore is written, the wizard is
  // not finished. If this ever returns 'show-dashboard', the sheet is destroyed.
  assert.equal(decideContent(true, true), 'wizard-owns-content');
});

test('a live wizard outranks the flag no matter what the flag says', () => {
  for (const v of [true, false, undefined, null, {}, 'done', 0, 1]) {
    assert.equal(
      decideContent(true, v),
      'wizard-owns-content',
      `a live wizard was evicted by provisioned=${JSON.stringify(v)}`,
    );
  }
});

test('with no wizard live, the flag decides — and FAILS CLOSED', () => {
  // The one and only way to reach the dashboard: a hard true, and no wizard on screen.
  assert.equal(decideContent(false, true), 'show-dashboard');
  // Everything else is setup. A rejected isProvisioned() lands here as `false` (the `ask`
  // fallback), and an owner shown setup twice is recoverable; an owner shown an empty dashboard
  // over real data is told their books are empty.
  for (const v of [false, undefined, null, {}, 'true', 1]) {
    assert.equal(decideContent(false, v), 'show-wizard', `${JSON.stringify(v)} must not skip setup`);
  }
});

test('COMPLETION IS REACHABLE: the wizard must not be able to wedge itself on screen forever', () => {
  // The mirror-image hazard of the guard above. If a live wizard always wins, then the shell
  // MUST clear its handle before routing on completion — otherwise `onDone` → route →
  // 'wizard-owns-content' → the wizard sits on the done screen for good, and the dashboard is
  // as unreachable as the sheet used to be.
  //
  // main.ts clears `disposeWizard` before calling `route()`, which is this call:
  assert.equal(decideContent(false, true), 'show-dashboard');
});
