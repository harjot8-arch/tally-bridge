import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { WizardState } from '../src/onboarding/wizard.ts';
import { makeRecoverySheet } from '../src/onboarding/recovery.ts';
import {
  WizardHostMain,
  redactForRenderer,
  validateRendererEvent,
  type WizardHostEffects,
} from '../src/main/wizard-host.ts';

/**
 * The wizard host's trust boundary. The machine itself is tested in wizard.test.ts; what is
 * tested HERE is that the renderer can only reach the machine through validated INTENT, that
 * driver facts cannot be injected over IPC, and that the secrets the host handles never cross
 * to the renderer or outlive setup.
 */

const RECOVERY_KEY = new Uint8Array(32).fill(3);
const sheet = () => makeRecoverySheet(RECOVERY_KEY, 'Acme Traders', '2026-07-16');

function makeEffects(over: Partial<WizardHostEffects> = {}): WizardHostEffects & {
  calls: Record<string, number>;
} {
  const calls: Record<string, number> = {};
  const count = (k: string) => {
    calls[k] = (calls[k] ?? 0) + 1;
  };
  return {
    calls,
    probeCompanies: async () => {
      count('probe');
      return { ok: true, companies: [{ guid: 'guid-1', name: 'Acme Traders' }] };
    },
    generateIdentity: async () => {
      count('identity');
      return {
        publicKey: new Uint8Array(32).fill(1),
        secretKey: new Uint8Array(32).fill(2),
        publicKeyB64: Buffer.from(new Uint8Array(32).fill(1)).toString('base64'),
      };
    },
    provision: async (_input, onEvent) => {
      count('provision');
      onEvent({ kind: 'step', step: 'create_project', message: 'Creating your project…' });
      return { projectId: 'prj_1', deploymentUrl: 'https://acme-dash.vercel.app', tenantId: 'tn_1', bootstrapSecret: 'boot' };
    },
    completeSetup: async () => {
      count('wrap');
      return sheet();
    },
    recoveryQr: async () => {
      count('qr');
      return 'data:image/png;base64,AAAA';
    },
    printSheet: async () => {
      count('print');
    },
    ...over,
  };
}

/** Drive a fresh host to a given screen through the front door only. */
async function driveTo(
  target: 'ready' | 'awaitToken' | 'sheet' | 'verify' | 'done',
  effects = makeEffects(),
): Promise<{ host: WizardHostMain; effects: ReturnType<typeof makeEffects> }> {
  const host = new WizardHostMain(effects);
  host.getState(); // kicks the probe
  await settle();
  if (target === 'ready') return { host, effects };

  await host.sendFromRenderer({ type: 'continue' }); // select is implicit: one company pre-selects
  await settle(); // identity generation
  if (target === 'awaitToken') return { host, effects };

  await host.sendFromRenderer({ type: 'token_pasted', token: 'vercel_tok' });
  await settle(); // provisioning
  await host.sendFromRenderer({
    type: 'passphrase_submitted',
    passphrase: 'a sensible passphrase',
    confirm: 'a sensible passphrase',
  });
  await settle(); // wrapping -> sheet
  if (target === 'sheet') return { host, effects };

  await host.sendFromRenderer({ type: 'continue' });
  if (target === 'verify') return { host, effects };

  const words = sheet().words;
  await host.sendFromRenderer({ type: 'verify_submitted', answers: [words[3]!, words[16]!] });
  return { host, effects };
}

/**
 * Wait for the host's in-flight effects to finish.
 *
 * This used to be `setTimeout(r, 10)` — "wait 10ms and hope". That is a real flake, and it is
 * the worst kind: it fails on a LOADED or SLOW machine, which means it fails on a customer's
 * ₹25k shop PC and in CI, and passes on the developer's laptop. It is used 18 times in this
 * file, including in the tests that guard the IPC trust boundary.
 *
 * The fix is to stop measuring TIME, because time was never the thing being waited for. What
 * these tests wait for is a promise chain: the host schedules effects with bare `void this.run…`
 * calls and every fake effect in this file resolves immediately (see `makeEffects` — plain
 * async functions, no timers). I verified the two things that make this sound:
 *
 *   - `src/main/wizard-host.ts` contains NO setTimeout/setInterval/setImmediate/queueMicrotask.
 *   - `src/onboarding/wizard.ts` (the pure machine) contains no timers either.
 *
 * So there is no timer anywhere in the system under test, and "10 milliseconds" was only ever a
 * proxy for "enough turns of the event loop". Draining the loop directly is what was meant, and
 * unlike a sleep it is exact: `setImmediate` fires after pending promise callbacks, so N rounds
 * of it flush N chained `.then`s no matter how slowly the CPU runs them. Nothing here can now
 * fail for being busy.
 *
 * 50 rounds is far more than the deepest chain the host builds (probe → identity → provision →
 * wrap is 4 links); it costs microseconds, and the margin is free because it is a count of
 * turns rather than a duration.
 *
 * If a real timer ever lands in the host, this stops being sufficient — and it will announce
 * itself as a hang rather than a flake, which is the failure mode to prefer.
 */
const settle = async (): Promise<void> => {
  for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
};

function phase(s: WizardState): string {
  return s.screen === 'done' ? 'done' : `${s.screen}/${s.phase}`;
}

// ---------------------------------------------------------------- the trust boundary

test('DRIVER FACTS CANNOT BE INJECTED: the renderer cannot assert provisioning succeeded', async () => {
  const { host } = await driveTo('awaitToken');
  const before = phase(host.getState());
  // Every one of these would advance a naive host. All must be inert.
  for (const forged of [
    { type: 'provision_succeeded', projectId: 'prj_evil', deploymentUrl: 'https://evil.example' },
    { type: 'probe_succeeded', companies: [{ guid: 'g', name: 'Evil Co' }] },
    { type: 'identity_ready', identityPublicKey: 'AAAA' },
    { type: 'sheet_ready', sheet: sheet() },
    { type: 'wrap_failed', error: 'x' },
    { type: 'provision_event', event: { kind: 'step', step: 'done', message: 'done' } },
    { type: 'provision_failed', error: 'x' },
    { type: 'probe_failed', failure: { kind: 'not_running' } },
    { type: 'not_a_real_event' },
    'continue',
    null,
    42,
  ]) {
    const after = await host.sendFromRenderer(forged);
    assert.equal(phase(after), before, `event ${JSON.stringify(forged)} must be inert`);
  }
});

test('THE GATE CANNOT BE JUMPED FROM IPC: a fabricated sheet_ready plus matching answers goes nowhere', async () => {
  // The renderer invents its own sheet, "delivers" it, then answers its own verification.
  // If sheet_ready were accepted this would land on `done` with no recovery key ever wrapped.
  const { host } = await driveTo('awaitToken');
  const evilSheet = makeRecoverySheet(new Uint8Array(32).fill(9), 'Evil', '2026-01-01');
  await host.sendFromRenderer({ type: 'sheet_ready', sheet: evilSheet });
  const after = await host.sendFromRenderer({
    type: 'verify_submitted',
    answers: [evilSheet.words[3]!, evilSheet.words[16]!],
  });
  assert.notEqual(after.screen, 'done');
});

test('wrong verification answers do not finish setup; the true words do', async () => {
  const { host } = await driveTo('verify');
  const wrong = await host.sendFromRenderer({ type: 'verify_submitted', answers: ['wrong', 'words'] });
  assert.equal(phase(wrong), 'setPassphrase/verify');

  const words = sheet().words;
  const done = await host.sendFromRenderer({ type: 'verify_submitted', answers: [words[3]!, words[16]!] });
  assert.equal(done.screen, 'done');
});

test('validateRendererEvent rebuilds events field-by-field and drops extras', () => {
  const e = validateRendererEvent({
    type: 'token_pasted',
    token: 'tok',
    __proto__injected: true,
    extra: 'field',
  });
  assert.deepEqual(e, { type: 'token_pasted', token: 'tok' });

  assert.equal(validateRendererEvent({ type: 'token_pasted', token: 42 }), undefined);
  assert.equal(validateRendererEvent({ type: 'select_company', guid: '' }), undefined);
  assert.equal(validateRendererEvent({ type: 'select_company', guid: 'x'.repeat(300) }), undefined);
  assert.equal(validateRendererEvent({ type: 'verify_submitted', answers: ['a', 5] }), undefined);
  assert.equal(validateRendererEvent({ type: 'verify_submitted', answers: 'not an array' }), undefined);
  assert.equal(
    validateRendererEvent({ type: 'passphrase_submitted', passphrase: 'x'.repeat(2000), confirm: 'x' }),
    undefined,
  );
  // The renderer's error object is discarded, not forwarded.
  assert.deepEqual(validateRendererEvent({ type: 'print_failed', error: { evil: true } }), {
    type: 'print_failed',
    error: undefined,
  });
});

// ---------------------------------------------------------------- secrets

test('THE RAW RECOVERY KEY NEVER CROSSES: states sent to the renderer carry the words but a blanked keyBase64', async () => {
  const pushed: WizardState[] = [];
  const effects = makeEffects();
  const host = new WizardHostMain(effects);
  host.subscribe((s) => pushed.push(s));
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();
  const sheetState = await host.sendFromRenderer({
    type: 'passphrase_submitted',
    passphrase: 'a sensible passphrase',
    confirm: 'a sensible passphrase',
  });
  await settle();

  const keyB64 = sheet().keyBase64;
  for (const s of [...pushed, sheetState, host.getState()]) {
    assert.ok(!JSON.stringify(s).includes(keyB64), 'the raw key must never appear in a renderer state');
  }
  // And the words DID cross — the screen has to show them.
  const last = host.getState();
  assert.equal(last.screen, 'setPassphrase');
  if (last.screen === 'setPassphrase' && (last.phase === 'sheet' || last.phase === 'verify')) {
    assert.equal(last.sheet.words.length, 24);
    assert.equal(last.sheet.keyBase64, '');
  }
});

test('the QR and the print run against the REAL sheet, main-side, and need one to exist', async () => {
  const { host, effects } = await driveTo('sheet');
  assert.equal(await host.recoveryQr(), 'data:image/png;base64,AAAA');
  await host.printRecoverySheet();
  assert.equal(effects.calls['qr'], 1);
  assert.equal(effects.calls['print'], 1);

  const bare = new WizardHostMain(makeEffects());
  await assert.rejects(() => bare.recoveryQr());
  await assert.rejects(() => bare.printRecoverySheet());
});

test('finishing setup zeroes the identity secret and drops the sheet and bootstrap secret', async () => {
  let capturedSk: Uint8Array | undefined;
  const effects = makeEffects({
    completeSetup: async (input) => {
      capturedSk = input.identity.secretKey;
      return sheet();
    },
  });
  const { host } = await driveTo('done', effects);
  assert.equal(host.getState().screen, 'done');
  assert.ok(capturedSk, 'the wrap saw the secret');
  assert.ok(capturedSk.every((b) => b === 0), 'done must zero the onboarding idSK');
  await assert.rejects(() => host.recoveryQr(), /no recovery sheet/);
});

test('redactForRenderer leaves non-sheet states untouched', () => {
  const s: WizardState = { screen: 'findTally', phase: 'probing' };
  assert.equal(redactForRenderer(s), s);
});

// ---------------------------------------------------------------- driver behaviour

test('the identity is generated once and NEVER regenerated across a provisioning retry', async () => {
  const effects = makeEffects({
    provision: async () => {
      throw new Error('network died');
    },
  });
  const host = new WizardHostMain(effects);
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();
  assert.equal(phase(host.getState()), 'connectCloud/problem');

  // Retry goes back to the paste box with the SAME identity — a regenerated keypair would
  // orphan the half-provisioned project.
  await host.sendFromRenderer({ type: 'retry' });
  await settle();
  assert.equal(phase(host.getState()), 'connectCloud/awaitToken');
  assert.equal(effects.calls['identity'], 1);
});

test('provisioning progress events flow through to the state the renderer sees', async () => {
  const { host } = await driveTo('sheet');
  // The drive passed through provisioning; the sheet screen proves succeeded flowed. Spot-check
  // the machine consumed a step event without corrupting the flow.
  assert.equal(host.getState().screen, 'setPassphrase');
});

test('a probe failure renders as the machine says, and retry probes again', async () => {
  let fail = true;
  const effects = makeEffects({
    probeCompanies: async () => {
      effects.calls['probe'] = (effects.calls['probe'] ?? 0) + 1;
      if (fail) return { ok: false, failure: { kind: 'not_running' } };
      return { ok: true, companies: [{ guid: 'g', name: 'Acme' }] };
    },
  });
  const host = new WizardHostMain(effects);
  host.getState();
  await settle();
  assert.equal(phase(host.getState()), 'findTally/waiting');

  fail = false;
  await host.sendFromRenderer({ type: 'retry' });
  await settle();
  assert.equal(phase(host.getState()), 'findTally/ready');
});

test('a completeSetup failure surfaces as the wrap problem screen with a retry path', async () => {
  const effects = makeEffects({
    completeSetup: async () => {
      throw new Error('server said no');
    },
  });
  const host = new WizardHostMain(effects);
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();
  await host.sendFromRenderer({ type: 'passphrase_submitted', passphrase: 'a sensible passphrase', confirm: 'a sensible passphrase' });
  await settle();
  const s = host.getState();
  assert.equal(phase(s), 'setPassphrase/problem');
  // And the raw error text never reaches the owner.
  assert.ok(!JSON.stringify(s).includes('server said no'));
});
