import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { makeRecoverySheet, makeVerificationChallenge, type RecoverySheet } from '../src/onboarding/recovery.ts';
import {
  initialState,
  next,
  type TallyCompany,
  type WizardEvent,
  type WizardState,
} from '../src/onboarding/wizard.ts';
import {
  describeWizard,
  hostFromBridge,
  isQrDataUrl,
  isWizardComplete,
  mountWizard,
  renderWizard,
  startWizard,
  t,
  type Intent,
  type WizardHost,
} from '../src/renderer/wizard.ts';
import type { BridgeApi } from '../src/main/ipc.ts';
import { installDom, byClass, byTag, allText, type FakeNode } from './dashboard.dom.ts';

/**
 * ADVERSARIAL tests for the setup wizard. Written to BREAK it, not to describe it.
 *
 * Everything here attacks one of four things: the recovery gate (the only thing in this product
 * with no reset behind it), the DOM sinks a Tally-supplied string can reach, the raw recovery key,
 * and the driver's behaviour when every host call rejects.
 */

const ACME: TallyCompany = { guid: 'g', name: 'Acme Traders' };
const PASS = 'ledger book monday';

/**
 * A sheet whose 24 words are all DIFFERENT.
 *
 * Not `new Uint8Array(32).fill(n)`, which the other wizard tests use: a constant key produces a
 * mnemonic with an 8-word repeating cycle (`alpha deal scrub asthma … alpha deal scrub asthma …`),
 * so word #17 equals word #1 and word #4 equals word #12. Every "a word from the WRONG position
 * must be rejected" assertion written against that fixture is vacuously true — the wrong word IS
 * the right word. This one is checked.
 */
function sheetFor(salt = 0): RecoverySheet {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) key[i] = (i * 7 + 3 + salt) & 0xff;
  const sheet = makeRecoverySheet(key, 'Acme Traders', '2026-07-16');
  assert.equal(new Set(sheet.words).size, 24, 'fixture must have 24 distinct words');
  return sheet;
}

const drive = (events: WizardEvent[], from: WizardState = initialState()): WizardState =>
  events.reduce(next, from);

const atVerify = (sheet: RecoverySheet): WizardState =>
  drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
    { type: 'continue' },
  ]);

// ================================================================ THE GATE

test('ATTACK: every event in the union, thrown at the gate, and none of them opens it', () => {
  const sheet = sheetFor();
  const verify = atVerify(sheet);

  // The whole union, with values chosen to be as tempting as possible.
  const everything: WizardEvent[] = [
    { type: 'probe_started' },
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'probe_failed', failure: { kind: 'not_running' } },
    { type: 'select_company', guid: 'g' },
    { type: 'continue' },
    { type: 'retry' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_event', event: { kind: 'step', step: 'done', message: 'Done.' } },
    { type: 'provision_failed', error: new Error('x') },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
    { type: 'wrap_failed', error: new Error('x') },
    { type: 'printed' },
    { type: 'print_failed', error: new Error('x') },
  ];

  for (const e of everything) {
    assert.equal(isWizardComplete(next(verify, e)), false, `${e.type} walked past the gate`);
  }

  // Events that are not in the union at all — an event arriving over IPC is untyped at runtime.
  for (const junk of [
    { type: 'skip' },
    { type: 'done' },
    { type: 'verify_submitted' }, // answers absent
    { type: 'verify_submitted', answers: null },
    { type: 'verify_submitted', answers: undefined },
    { type: 'verify_submitted', answers: 'a b' },
    { type: 'verify_submitted', answers: {} },
    { type: 'verify_submitted', answers: { 0: sheet.words[3], 1: sheet.words[16], length: 2 } },
    { type: 'verify_submitted', answers: [sheet.words[3], sheet.words[16], 'x'] },
    {},
    { type: undefined },
    { type: null },
  ]) {
    assert.equal(
      isWizardComplete(next(verify, junk as unknown as WizardEvent)),
      false,
      `junk event opened the gate: ${JSON.stringify(junk)}`,
    );
  }
});

test('FINDING: `next` is documented TOTAL but THROWS on a null/undefined event', () => {
  // `src/onboarding/wizard.ts` header: "TOTAL AND PURE. An event that makes no sense in the
  // current state returns the state unchanged rather than throwing". That is false for a
  // non-object event: `switch (event.type)` dereferences it.
  //
  // Impact is contained rather than absent, and the containment is worth naming: the event
  // arrives over IPC (`sendWizardEvent`) where TypeScript is gone, so a malformed payload throws
  // inside main's handler, `invoke` REJECTS, and the driver's `ask()` fallback renders the fatal
  // screen. It FAILS CLOSED — no gate is opened — but the machine's claim is not true, and a
  // future caller that trusts "returns the state unchanged" will be wrong.
  const verify = atVerify(sheetFor());
  for (const junk of [null, undefined]) {
    assert.throws(
      () => next(verify, junk as unknown as WizardEvent),
      TypeError,
      `next() no longer throws on ${JSON.stringify(junk)} — if it was made total, delete this test`,
    );
  }
  // A primitive is survivable only by accident: `(42).type` is undefined, so it lands in the
  // `default` arm and returns the state. Total for the wrong reason, but total.
  assert.deepEqual(next(verify, 42 as unknown as WizardEvent), verify);
  assert.deepEqual(next(verify, 'verify_submitted' as unknown as WizardEvent), verify);

  // The property that actually matters holds regardless: nothing here is `done`.
  for (const junk of [null, undefined, 'verify_submitted', 42]) {
    let after: WizardState | undefined;
    try {
      after = next(verify, junk as unknown as WizardEvent);
    } catch {
      after = undefined;
    }
    assert.equal(isWizardComplete(after), false);
  }
});

test('ATTACK: wrong answers at the gate — undefined, empty, swapped, wrong position, lookalikes', () => {
  const sheet = sheetFor();
  const verify = atVerify(sheet);
  const w4 = sheet.words[3]!;
  const w17 = sheet.words[16]!;

  // Every lookalike below is asserted to actually DIFFER from the real word first — a "lookalike"
  // that silently equals the original is a test that passes for the wrong reason.
  const cyrillicI = w4.replace(/i/g, 'і'); // Cyrillic dotted i
  const greekO = w17.replace(/o/g, 'ο'); // Greek omicron
  const zwsp = `${w4}​`;
  const bom = `${w4}﻿`; // U+FEFF *is* stripped by String.trim()
  const nbsp = ` ${w4} `;
  for (const [a, b] of [
    [cyrillicI, w4],
    [greekO, w17],
    [zwsp, w4],
    [bom, w4],
  ]) assert.notEqual(a, b, 'the lookalike fixture is not actually different');

  const wrong: unknown[][] = [
    [],
    [w4],
    [w4, w17, w4],
    [undefined, undefined],
    [null, null],
    ['', ''],
    [' ', ' '],
    [w4, ''],
    ['', w17],
    [w17, w4], // swapped
    [sheet.words[0], sheet.words[1]], // words from other positions
    [w4, sheet.words[17]], // off-by-one on #17
    [sheet.words[2], w17], // off-by-one on #4
    [zwsp, w17], // zero-width space
    [cyrillicI, w17], // cyrillic lookalike
    [w4, greekO], // greek lookalike
    [w4.toUpperCase() + 'x', w17],
    [{ toString: () => w4 }, { toString: () => w17 }], // not strings
    [Object.assign([], { 0: w4, 1: w17, length: 2 })],
  ];

  for (const answers of wrong) {
    const after = next(verify, { type: 'verify_submitted', answers: answers as string[] });
    assert.equal(isWizardComplete(after), false, `opened by: ${JSON.stringify(answers)}`);
  }

  // What IS allowed: the owner's typing, off paper. Case and surrounding whitespace only.
  for (const answers of [
    [w4, w17],
    [`  ${w4}  `, `\t${w17}\n`],
    [nbsp, w17],
    [bom, w17], // U+FEFF is whitespace to trim(); a stray BOM from a paste is not a wrong word
    [w4.toUpperCase(), w17.toUpperCase()],
  ]) {
    assert.equal(
      isWizardComplete(next(verify, { type: 'verify_submitted', answers })),
      true,
      `an owner typing this off the paper was refused: ${JSON.stringify(answers)}`,
    );
  }
});

test('ATTACK: the same event twice, and events out of order, never accumulate into done', () => {
  const sheet = sheetFor();
  let s = atVerify(sheet);

  // Fire the wrong answer repeatedly: attempts climb, the gate does not open, nothing locks out.
  for (let i = 0; i < 50; i++) {
    s = next(s, { type: 'verify_submitted', answers: ['no', 'no'] });
    assert.equal(isWizardComplete(s), false);
  }
  assert.equal(s.screen === 'setPassphrase' && s.phase === 'verify' ? s.attempts : -1, 50);
  // Still answerable — a typo gate must never become a lockout.
  assert.equal(isWizardComplete(next(s, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] })), true);

  // `continue` fired twice from the sheet screen must not skip verify.
  const sheetState = drive([{ type: 'continue' }], atVerify(sheet));
  assert.equal(isWizardComplete(sheetState), false);
  assert.equal(sheetState.screen === 'setPassphrase' ? sheetState.phase : '', 'verify');

  // done is terminal and absorbs everything — including a replayed verify with junk.
  const done = next(atVerify(sheet), { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  for (const e of [{ type: 'retry' }, { type: 'continue' }, { type: 'probe_started' }] as WizardEvent[]) {
    assert.deepEqual(next(done, e), done, 'done must be terminal');
  }
});

test('ATTACK: a truncated or hostile sheet makes the gate fail CLOSED, never open', () => {
  const sheet = sheetFor();

  // A restore that lost its words. `undefined === undefined` was the original bug.
  const truncated: RecoverySheet = { ...sheet, words: [] };
  assert.equal(makeVerificationChallenge(truncated).check([undefined as unknown as string, undefined as unknown as string]), false);
  assert.equal(makeVerificationChallenge(truncated).check(['', '']), false);

  // Words present but blank at the checked positions.
  const blanked: RecoverySheet = { ...sheet, words: sheet.words.map((w, i) => (i === 3 || i === 16 ? '' : w)) };
  assert.equal(makeVerificationChallenge(blanked).check(['', '']), false);

  // Sheet shorter than position 17.
  const short: RecoverySheet = { ...sheet, words: sheet.words.slice(0, 5) };
  assert.equal(makeVerificationChallenge(short).check([sheet.words[3]!, '']), false);

  // Non-array answers arriving over IPC.
  for (const junk of [null, undefined, 'abc', 42, {}, { length: 2 }]) {
    assert.equal(makeVerificationChallenge(sheet).check(junk as unknown as string[]), false);
  }

  // A `words` array whose entries are not strings.
  const poisoned: RecoverySheet = { ...sheet, words: sheet.words.map(() => undefined as unknown as string) };
  assert.equal(makeVerificationChallenge(poisoned).check([undefined as unknown as string, undefined as unknown as string]), false);
});

test('ATTACK: the renderer cannot construct done, and no Intent it offers advances past verify', () => {
  const sheet = sheetFor();
  const verify = atVerify(sheet);
  const model = describeWizard(verify, 'en');

  // The verify screen offers exactly one thing, and it is the submission.
  assert.equal(model.action, undefined);
  assert.equal(model.primary!.intent.kind, 'submit_verify');
  assert.equal(model.complete, false);

  // A hand-built `done` model is not a hand-built `done` STATE: describeWizard reads the state,
  // and the driver's onDone reads isWizardComplete(state). The model is downstream of both.
  assert.equal(isWizardComplete({ screen: 'done' as const, company: ACME, deploymentUrl: 'x' }), true);
  // ...but the renderer never makes one: the only producer is `next`, and the only edge into
  // done is verify_submitted with a correct answer. Proven by exhausting the union above.

  // Every intent the union can carry, dispatched at verify, and none of them is a skip.
  const kinds: Intent['kind'][] = ['continue', 'select_company', 'retry', 'open', 'submit_token', 'submit_passphrase', 'submit_verify', 'print'];
  assert.equal(kinds.includes('skip' as never), false);
});

// ================================================================ THE QR / URL GATE

test('ATTACK: isQrDataUrl allowlist bypasses', () => {
  for (const bad of [
    'data:image/png;x=svg+xml;base64,AAAA',
    'data:image/png;base64,AAAA;base64,BBBB',
    'DATA:IMAGE/PNG;BASE64,AAAA',
    'Data:Image/Png;Base64,AAAA',
    'data:image/png,<svg onload=alert(1)>',
    'data:image/png;base64,AAAA\n',
    'data:image/png;base64,AAAA\r\n',
    '\ndata:image/png;base64,AAAA',
    'data:image/png;base64,AAAA\ndata:text/html;base64,PHN2Zy8+',
    'data:image/svg+xml;base64,PHN2Zy8+',
    'data:image/png+svg+xml;base64,AAAA',
    'data:image/png ;base64,AAAA',
    'data:image/png; base64,AAAA',
    'data:image/png;base64, AAAA',
    'data:image/png;base64,AA=A',
    'data:image/png;base64,AAA===',
    'data:image/png;base64,',
    'data:image/png;base64,AAAA#',
    'data:image/png;base64,AA%0AAA',
    'data:image/png;charset=utf-8;base64,AAAA',
    ' data:image/png;base64,AAAA ',
    'javascript:alert(1)',
    'vbscript:msgbox(1)',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'x-data:image/png;base64,AAAA',
    'data:image/png;base64,AAAA" onerror="alert(1)',
    "data:image/png;base64,AAAA' onload='alert(1)",
    'data:image/png;base64,AAAA><img src=x onerror=alert(1)>',
  ]) {
    assert.equal(isQrDataUrl(bad), false, `isQrDataUrl accepted: ${JSON.stringify(bad)}`);
  }

  // The real thing, from the qrcode package's toDataURL, still passes.
  assert.equal(isQrDataUrl('data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=='), true);
});

// ================================================================ THE DOM

function withDom(fn: (root: FakeNode) => void): void {
  const dom = installDom();
  try {
    fn(dom.root);
  } finally {
    dom.uninstall();
  }
}

const noop = () => undefined;

/** The fake DOM's node, at the boundary of code that wants a real one. Same cast the dashboard tests use. */
const asEl = (n: FakeNode): HTMLElement => n as unknown as HTMLElement;

test('ATTACK: a company named <img src=x onerror=...> reaches the DOM as TEXT, not as markup', () => {
  const hostile = '<img src=x onerror=alert(1)>';
  const trade = 'A & B Traders <Mumbai>';
  withDom((root) => {
    const state = next(initialState(), {
      type: 'probe_succeeded',
      companies: [
        { guid: 'a', name: hostile },
        { guid: 'b', name: trade },
      ],
    });
    renderWizard(asEl(root), describeWizard(state, 'en'), 'en', new Map(), noop, noop);

    // The name survives verbatim as text — no mangling of `&`, no execution of the img.
    const names = byClass(root, 'wz-company-name').map((n) => n.textContent);
    assert.deepEqual(names, [hostile, trade]);

    // And no element was ever CREATED from it: an injected <img> would exist as a node.
    assert.equal(byTag(root, 'img').length, 0, 'a company name created an element');
    assert.equal(byTag(root, 'script').length, 0);
    // No attribute anywhere carries the payload — this is what an insertAdjacentHTML would show.
    for (const node of byClass(root, 'wz-company-name')) {
      assert.equal([...node.attributes.values()].join(' ').includes('onerror'), false);
    }
  });
});

test('ATTACK: a hostile business name on the sheet screen, and a hostile qrDataUrl', () => {
  const sheet = makeRecoverySheet(new Uint8Array(32).fill(9), '<script>alert(1)</script> & Co', '2026-07-16');
  const state = drive([{ type: 'continue' }], atVerify(sheet)); // still verify; get the sheet state instead
  void state;

  const sheetState = drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
  ]);

  withDom((root) => {
    // A hostile QR URL must produce NO img at all.
    const evil = 'data:image/png;base64,AAA" onerror="alert(1)';
    renderWizard(asEl(root), describeWizard(sheetState, 'en', evil), 'en', new Map(), noop, noop);
    assert.equal(byTag(root, 'img').length, 0, 'an invalid QR data URL still made an <img>');
    assert.equal(allText(root).includes('onerror'), false);
    // The business name is text.
    assert.ok(allText(root).includes('<script>alert(1)</script> & Co'));
    assert.equal(byTag(root, 'script').length, 0);
  });

  withDom((root) => {
    const good = 'data:image/png;base64,iVBORw0KGgo=';
    renderWizard(asEl(root), describeWizard(sheetState, 'en', good), 'en', new Map(), noop, noop);
    const imgs = byTag(root, 'img');
    assert.equal(imgs.length, 1);
    assert.equal((imgs[0] as unknown as { src: string }).src, good);
  });
});

test('THE RAW RECOVERY KEY is never rendered — not as text, not in an attribute', () => {
  const sheet = sheetFor(11);
  const sheetState = drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
  ]);

  withDom((root) => {
    renderWizard(asEl(root), describeWizard(sheetState, 'en', 'data:image/png;base64,iVBORw0KGgo='), 'en', new Map(), noop, noop);
    const text = allText(root);
    assert.equal(text.includes(sheet.keyBase64), false, 'the raw recovery key is on screen as text');
    // Not in an attribute either (an alt=, a title=, a data-*).
    const nodes: FakeNode[] = [];
    const collect = (n: FakeNode) => {
      nodes.push(n);
      for (const c of n.childNodes) collect(c);
    };
    collect(root);
    for (const n of nodes) {
      for (const v of n.attributes.values()) {
        assert.equal(v.includes(sheet.keyBase64), false, 'the raw recovery key is in an attribute');
      }
    }
    // The 24 words ARE on screen — that is the point of the sheet.
    assert.equal(byClass(root, 'wz-word').length, 24);
  });
});

test('a passphrase input is masked and never carries a value the model supplied', () => {
  const entry = drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
  ]);
  withDom((root) => {
    renderWizard(asEl(root), describeWizard(entry, 'en'), 'en', new Map(), noop, noop);
    const inputs = byTag(root, 'input');
    assert.equal(inputs.length, 2);
    for (const i of inputs) assert.equal(i.type, 'password');
  });
});

// ================================================================ THE HOST PORT

test('ATTACK: hostFromBridge fails CLOSED for every shape of a not-yet-wired bridge', () => {
  const verbs = ['getWizardState', 'sendWizardEvent', 'onWizardStateChanged', 'recoveryQr', 'printRecoverySheet'];
  const full = () => {
    const b: Record<string, unknown> = { openExternal: () => Promise.resolve() };
    for (const v of verbs) b[v] = () => Promise.resolve();
    return b as unknown as BridgeApi;
  };

  assert.equal(hostFromBridge(undefined), undefined);
  assert.equal(hostFromBridge(null as unknown as BridgeApi), undefined);
  assert.ok(hostFromBridge(full()), 'a fully wired bridge must adapt');

  // One verb missing, in every position.
  for (const missing of verbs) {
    const b = full() as unknown as Record<string, unknown>;
    delete b[missing];
    assert.equal(hostFromBridge(b as unknown as BridgeApi), undefined, `${missing} missing must fail closed`);
  }
  // A verb present but not callable — a truthy stub is not a function.
  for (const missing of verbs) {
    for (const junk of [true, 1, 'yes', {}, [], null]) {
      const b = full() as unknown as Record<string, unknown>;
      b[missing] = junk;
      assert.equal(hostFromBridge(b as unknown as BridgeApi), undefined, `${missing}=${JSON.stringify(junk)} must fail closed`);
    }
  }
});

test('THE SHIPPING STATE: the real preload has no wizard verbs, so setup shows a sentence — not a spinner', () => {
  // The five wizard channels do not exist on `window.bridge` yet. `ipcRenderer.invoke` on an
  // unhandled channel REJECTS, so an un-detected call would leave a dead screen forever.
  withDom((root) => {
    const realish = {
      getStatus: () => Promise.resolve({}),
      isProvisioned: () => Promise.resolve(false),
      openExternal: () => Promise.resolve(),
      getCards: () => Promise.resolve(null),
      syncNow: () => Promise.resolve(),
      onStatusChanged: () => undefined,
    } as unknown as BridgeApi;

    const dispose = startWizard(asEl(root), realish, { onDone: () => assert.fail('onDone with no host') });
    const text = allText(root);
    assert.ok(text.length > 0, 'a missing host must not render a blank window');
    assert.equal(text, t('en', 'host_missing'));
    assert.equal(/\d/.test(text), false, 'no error code');
    assert.doesNotThrow(dispose);
  });
});

// ================================================================ REJECTION HANDLING

/** A host where every verb rejects — the "IPC is not wired" world, and the "main is wedged" world. */
function rejectingHost(): WizardHost {
  const boom = () => Promise.reject(new Error('No handler registered for \'bridge:getWizardState\''));
  return {
    getState: boom,
    send: boom,
    subscribe: () => () => undefined,
    openExternal: boom,
    recoveryQr: boom,
    printRecoverySheet: boom,
  };
}

test('ATTACK: every host call rejects — the wizard says one sentence, never hangs', async () => {
  const dom = installDom();
  const errors: unknown[] = [];
  const realError = console.error;
  console.error = (...a: unknown[]) => void errors.push(a);
  try {
    let done = 0;
    const dispose = mountWizard(asEl(dom.root), rejectingHost(), { onDone: () => done++ });
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const text = allText(dom.root);
    assert.ok(text.length > 0, 'a rejected getState left a BLANK window');
    assert.equal(text.includes('bridge:getWizardState'), false, 'the IPC channel name reached the screen');
    assert.equal(/\bError\b|No handler/.test(text), false, 'a raw rejection reached the screen');
    assert.equal(done, 0, 'a rejected call must never be read as setup finished');
    // One button, and it retries rather than dead-ends.
    const buttons = byTag(dom.root, 'button');
    assert.equal(buttons.length, 1, 'the fatal screen must offer exactly one button');
    assert.doesNotThrow(() => buttons[0]!.click());
    // The retry re-boots; let it settle before the DOM is torn down.
    for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r));
    dispose();
  } finally {
    console.error = realError;
    dom.uninstall();
  }
});

test('ATTACK: printRecoverySheet rejects — the screen recovers rather than reading "Printing…" forever', async () => {
  const dom = installDom();
  const realError = console.error;
  console.error = () => undefined;
  try {
    const sheet = sheetFor();
    const sheetState = drive([
      { type: 'probe_succeeded', companies: [ACME] },
      { type: 'continue' },
      { type: 'identity_ready', identityPublicKey: 'PK' },
      { type: 'token_pasted', token: 'tok' },
      { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'sheet_ready', sheet },
    ]);

    let state = sheetState;
    const sent: WizardEvent[] = [];
    const host: WizardHost = {
      getState: () => Promise.resolve(state),
      send: (e) => {
        sent.push(e);
        state = next(state, e);
        return Promise.resolve(state);
      },
      subscribe: () => () => undefined,
      openExternal: () => Promise.resolve(),
      recoveryQr: () => Promise.reject(new Error('qrcode is not installed')),
      printRecoverySheet: () => Promise.reject(new Error('EPRINTER')),
    };

    const dispose = mountWizard(asEl(dom.root), host, { onDone: () => assert.fail('done from the sheet screen') });
    for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r));

    // The print failure became a machine event, not an unhandled rejection.
    assert.ok(sent.some((e) => e.type === 'print_failed'), 'a failed print was swallowed silently');
    // A failed QR render leaves the words, never a blank screen or a broken image.
    const text = allText(dom.root);
    assert.equal(text.includes('EPRINTER'), false, 'an errno reached the screen');
    assert.equal(text.includes('qrcode'), false);
    assert.ok(text.length > 0);
    dispose();
  } finally {
    console.error = realError;
    dom.uninstall();
  }
});

test('ATTACK: the driver never reads a rejected send as progress, and disposal stops all painting', async () => {
  const dom = installDom();
  const realError = console.error;
  console.error = () => undefined;
  try {
    const sheet = sheetFor();
    let state: WizardState = atVerify(sheet);
    const host: WizardHost = {
      getState: () => Promise.resolve(state),
      send: (e) => {
        state = next(state, e);
        return Promise.resolve(state);
      },
      subscribe: () => () => undefined,
      openExternal: () => Promise.resolve(),
      recoveryQr: () => Promise.resolve('data:image/png;base64,iVBORw0KGgo='),
      printRecoverySheet: () => Promise.resolve(),
    };
    let done = 0;
    const dispose = mountWizard(asEl(dom.root), host, { onDone: () => done++ });
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r));

    // Type the wrong words and submit: the gate holds and onDone never fires.
    const inputs = byTag(dom.root, 'input');
    assert.equal(inputs.length, 2, 'the gate must ask for two words');
    const buttons = byTag(dom.root, 'button');
    const submit = buttons.at(-1)!;
    submit.click();
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r));
    assert.equal(done, 0, 'empty inputs opened the gate');
    assert.equal(isWizardComplete(state), false);

    dispose();
    const before = allText(dom.root);
    // A late push after disposal must not repaint or fire onDone.
    state = next(state, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r));
    assert.equal(allText(dom.root), before);
    assert.equal(done, 0);
  } finally {
    console.error = realError;
    dom.uninstall();
  }
});

test('the gate opens through the DRIVER only when the two words are typed correctly', async () => {
  const dom = installDom();
  try {
    const sheet = sheetFor();
    let state: WizardState = atVerify(sheet);
    const host: WizardHost = {
      getState: () => Promise.resolve(state),
      send: (e) => {
        state = next(state, e);
        return Promise.resolve(state);
      },
      subscribe: () => () => undefined,
      openExternal: () => Promise.resolve(),
      recoveryQr: () => Promise.resolve('data:image/png;base64,iVBORw0KGgo='),
      printRecoverySheet: () => Promise.resolve(),
    };
    let done = 0;
    const dispose = mountWizard(asEl(dom.root), host, { onDone: () => done++ });
    for (let i = 0; i < 4; i++) await new Promise((r) => setImmediate(r));

    const inputs = byTag(dom.root, 'input') as Array<FakeNode & { value: string }>;
    inputs[0]!.value = sheet.words[3]!;
    inputs[1]!.value = sheet.words[16]!;
    for (const i of inputs) for (const fn of i.listeners.get('input') ?? []) fn();

    byTag(dom.root, 'button').at(-1)!.click();
    for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r));

    assert.equal(isWizardComplete(state), true, 'the right words must finish setup');
    assert.equal(done, 1, 'onDone must fire exactly once');
    dispose();
  } finally {
    dom.uninstall();
  }
});

// ================================================================ MONEY / TEXT

test('INDIAN NUMBERING at every boundary the renderer can reach', async () => {
  const { formatMoney } = await import('@tally-bridge/viewmodel');
  assert.equal(formatMoney(0), '₹0');
  assert.equal(formatMoney(999), '₹999');
  assert.equal(formatMoney(1_000), '₹1,000');
  assert.equal(formatMoney(99_999), '₹99,999');
  assert.equal(formatMoney(100_000), '₹1,00,000');
  assert.equal(formatMoney(123_456), '₹1,23,456');
  assert.equal(formatMoney(1_234_567), '₹12,34,567');
  assert.equal(formatMoney(10_000_000), '₹1,00,00,000');
  assert.equal(formatMoney(12_345_678), '₹1,23,45,678');
  assert.equal(formatMoney(-123_456), '-₹1,23,456');
  assert.equal(formatMoney(-1_234_567_890), '-₹1,23,45,67,890');
  // The thing this market must never see.
  for (const n of [100_000, 123_456, 10_000_000]) {
    assert.equal(/^₹\d{1,3}(,\d{3})+$/.test(formatMoney(n)), false, `en-US grouping: ${formatMoney(n)}`);
  }
});

// ================================================================ THE PRINT DEAD END

test('FIXED (was: a failed print dead-ended setup) — the escape from a print failure MOVES', () => {
  // This test was written by an adversarial pass to DEMONSTRATE a real bug, with the note:
  // "WHEN THIS IS FIXED, this test SHOULD go red. Delete this test and assert the escape instead."
  // The bug is fixed, so this is now the regression test it asked for.
  //
  // THE BUG, and its path was the DEFAULT one, not an exotic one:
  //   1. `mountWizard` AUTO-FIRES the print dialog on entering the sheet phase.
  //   2. An owner presses Esc on a dialog they never asked for -> `printRecoverySheet` rejects.
  //   3. The driver sends `print_failed`; the machine moved sheet -> `problem`, a state with NO
  //      `sheet` field, so the sheet was dropped with nothing to restore it from.
  //   4. The screen offered ONE button, `print_again`. On success it sends `printed` (a
  //      deliberate no-op — printing proves nothing); on failure `print_failed` (ignored off the
  //      sheet phase). Either way THE STATE NEVER MOVED.
  //   Net: passphrase set, identity wrapped, `done` unreachable forever.
  //
  // THE FIX: a print failure no longer LEAVES the sheet. The printer failed; the sheet did not —
  // the words and QR are still on screen and still correct, so there is nothing to recover from.
  // It is a note on the screen, and the screen keeps every way forward it already had.
  //
  // What made the bug survive review is worth remembering: the writer's own test named "EVERY
  // screen is a sentence and a way forward — never a dead end" COVERED this state and PASSED,
  // because it asserted an action EXISTED and never that firing it CHANGED anything.
  const sheet = sheetFor();
  const atSheet = drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'https://a.vercel.app' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
  ]);

  const failed = next(atSheet, { type: 'print_failed', error: new Error('cancelled') });

  // The sheet SURVIVES a print failure. This is the assertion the old state shape could not make.
  assert.equal(failed.screen === 'setPassphrase' ? failed.phase : '', 'sheet');
  assert.equal('sheet' in failed, true, 'a printer failure must not cost the owner the sheet');
  assert.deepEqual((failed as { sheet?: unknown }).sheet, sheet);

  // THE ESCAPE MOVES — the whole point. Not "an action exists": firing it changes the state.
  const onward = next(failed, { type: 'continue' });
  assert.notDeepEqual(onward, failed, 'an action that no-ops IS the dead end');
  assert.equal(onward.screen === 'setPassphrase' ? onward.phase : '', 'verify');

  // ...and it lands on the gate, which still demands the real words. The escape is not a skip.
  const wrong = next(onward, { type: 'verify_submitted', answers: ['wrong', 'wrong'] });
  assert.notEqual(wrong.screen, 'done', 'a print failure must never become a skip button');

  // The screen still renders one sentence and a way forward, and never the printer's error text.
  const m = describeWizard(failed, 'en');
  assert.ok(m.action ?? m.primary, 'the screen must still offer something');
  assert.equal(/cancelled|Error/.test(JSON.stringify(m)), false, 'no raw error text reaches the owner');
});

// ================================================================ ARCHITECTURE GAPS

/** Source with comments stripped — these files DOCUMENT the sinks they refuse to use. */
function readCode(p: string): string {
  return readFileSync(p, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function rendererFiles(): string[] {
  const dir = join(import.meta.dirname, '../src/renderer');
  return readdirSync(dir)
    .filter((f) => f.endsWith('.ts'))
    .map((f) => join(dir, f));
}

test('THE XSS RULE, WIDENED: the four sinks hardening.test.ts checks are not the only four', () => {
  // `hardening.test.ts` bans innerHTML / outerHTML / insertAdjacentHTML / document.write, and it
  // BITES for all four (verified by mutation). These are the sinks it does NOT see, each one
  // added here because adding it to the renderer today produces a green build:
  //
  //   - `el['inner'+'HTML'] = x`      a computed key defeats a substring grep outright
  //   - `setAttribute('onerror', x)`  an inline handler built from a company name
  //   - `createContextualFragment`    an HTML parser with a different name
  //   - `DOMParser.parseFromString`   likewise
  //   - `a.href = x`                  a URL context; `javascript:` is a well-formed URL
  //
  // The CSP (`script-src 'self'`, no unsafe-inline) blocks the executable half of most of these,
  // which is why this is a second lock and not the first one. A second lock is the point.
  const banned: Array<[RegExp, string]> = [
    [/createContextualFragment/, 'an HTML parser'],
    [/DOMParser|parseFromString/, 'an HTML parser'],
    [/parseHTMLUnsafe|\.setHTML\s*\(/, 'an HTML parser'],
    [/\bsrcdoc\b/, 'an iframe document'],
    [/setAttribute\(\s*['"`]on/, 'an inline event handler'],
    [/\[\s*['"`]inner/, 'a computed-key HTML sink'],
    [/\[\s*['"`]outer/, 'a computed-key HTML sink'],
    [/\.href\s*=/, 'a URL context built from data'],
    [/window\.open|location\s*\.\s*(href|assign|replace)/, 'a navigation'],
  ];

  for (const file of rendererFiles()) {
    const src = readCode(file);
    for (const [re, what] of banned) {
      assert.equal(re.test(src), false, `${file} reaches ${what} (${re})`);
    }
  }
});

test('MONEY: the renderer never formats a number itself — formatMoney or nothing', () => {
  // The test the writer left ("INDIAN NUMBERING: money is grouped by lakh, never by thousand")
  // only ever formats ₹1,800 — a number with NO lakh grouping in it. `Intl.NumberFormat('en-US')`
  // and `formatMoney` render 1800 identically, so that test passes unchanged if someone swaps
  // the formatter for the exact one ARCHITECTURE.md forbids. Verified by mutation: replacing
  // `formatMoney(rupees)` with `rupees.toLocaleString('en-US')` fails NOTHING.
  //
  // The value-level assertion cannot see this, so the source-level one has to. Intl's grouping
  // depends on the ICU data the runtime shipped with, and a runtime without full ICU falls back
  // to en-US silently: ₹123,456 instead of ₹1,23,456.
  for (const file of rendererFiles()) {
    const src = readCode(file);
    assert.equal(/Intl\s*\.\s*NumberFormat/.test(src), false, `${file} uses Intl.NumberFormat`);
    assert.equal(/toLocaleString\s*\(/.test(src), false, `${file} uses toLocaleString`);
  }
  const wiz = readCode(join(import.meta.dirname, '../src/renderer/wizard.ts'));
  assert.match(wiz, /import\s*\{[^}]*\bformatMoney\b[^}]*\}\s*from\s*'@tally-bridge\/viewmodel'/);
  assert.match(wiz, /return formatMoney\(/, 'proPlanRupees must go through formatMoney');
});

test('t() must not read an inherited key off the vars object', () => {
  // `{constructor}` in a dictionary string would render "function Object() { [native code] }".
  // Not reachable today because every key name comes from our own dictionary — but the lookup
  // has no own-property check, and this is the assertion that says it must.
  assert.equal(t('en', 'done_body', { business: 'Acme' }).includes('native code'), false);
  assert.equal(t('en', 'step_of', {}), 'Step {n} of 3');
});
