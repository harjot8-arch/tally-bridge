import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IsoDate, SectionPayload } from '@tally-bridge/core';
import {
  generateIdentity,
  makeAad,
  sealSection,
  sodiumReady,
  type DeviceRoster,
} from '@tally-bridge/crypto';
import { buildCards } from '../src/main/reader.ts';
import type { StoredSnapshot } from '../src/main/snapshots.ts';
import { RosterMarkStore } from '../src/main/snapshots.ts';
import { makeRecoverySheet } from '../src/onboarding/recovery.ts';
import { WizardHostMain, type WizardHostEffects } from '../src/main/wizard-host.ts';
import type { WizardState } from '../src/onboarding/wizard.ts';

/**
 * ADVERSARIAL AUDIT. Written to BREAK the backend, not to document it.
 *
 * The two findings this file pins:
 *
 *   1. THE GATE. wizard-host.test.ts throws driver facts at `sendFromRenderer` from the
 *      `awaitToken` phase — the ONE phase where the pure machine ignores them anyway. Those
 *      tests stay GREEN with `validateRendererEvent` deleted entirely, so they do not test the
 *      trust boundary they are named for. The boundary IS load-bearing: at `provisioning` and
 *      `wrapping` the machine ACCEPTS the matching driver fact, which is how the real driver
 *      advances it. These tests inject there, and they fail if the boundary is removed.
 *
 *   2. THE FORGERY, verified independently rather than taken on trust: a server that holds
 *      IDENTITY_PUBKEY mints a fully self-consistent envelope for the RIGHT slot under the REAL
 *      deviceId, and `getCards` must still refuse it.
 */

// ================================================================== THE FORGERY, END TO END

const TENANT = 't_1';
const DEVICE = 'dev_001';
const AS_OF: IsoDate = '2026-07-16';
const GUID = 'guid-acme';

const sodium = await sodiumReady();
const identity = await generateIdentity();
const realDevice = sodium.crypto_sign_keypair();
/** The malicious server's OWN signing key. It has IDENTITY_PUBKEY and knows the real deviceId. */
const serverKp = sodium.crypto_sign_keypair();
const roster: DeviceRoster = [{ deviceId: DEVICE, publicKey: realDevice.publicKey }];

const cash = (rupees: string): SectionPayload => ({
  section: 'cash_bank',
  rows: [{ companyGuid: GUID, asOf: AS_OF, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing: rupees }],
});

let seq = 0;
async function slot(payload: SectionPayload, signer: Uint8Array): Promise<StoredSnapshot> {
  const aad = makeAad({
    tenantId: TENANT,
    deviceId: DEVICE,
    companyGuid: GUID,
    section: payload.section,
    asOf: AS_OF,
    snapshotTs: 1_000_000,
    seq: ++seq,
  });
  const env = await sealSection(payload, aad, identity.publicKey, signer);
  return {
    companyGuid: GUID,
    section: payload.section,
    asOf: AS_OF,
    contentHash: env.contentHash,
    storedAt: 1,
    envelope: JSON.stringify(env),
  };
}

const readerInputs = (slots: StoredSnapshot[]) => ({
  slots,
  unreadable: 0,
  tenantId: TENANT,
  identityPublicKey: identity.publicKey,
  identitySecretKey: identity.secretKey,
  roster,
  log: () => {},
});

test('THE FORGERY: a server-minted envelope — right slot, right deviceId, fresh CEK sealed to idPK, matching contentHash — is REFUSED by getCards', async () => {
  // Sanity: the genuine article renders, so a refusal below is about the signer and nothing else.
  const genuine = await buildCards(readerInputs([await slot(cash('-1234.50'), realDevice.privateKey)]));
  assert.equal(genuine.state, 'ready');
  assert.equal(genuine.state === 'ready' && genuine.companies[0]!.cashBank!.total.paise, 123450);

  // The forgery. Everything the server can compute, it computed correctly. Only the roster stops it.
  const forged = await buildCards(readerInputs([await slot(cash('-99999999.00'), serverKp.privateKey)]));
  assert.notEqual(forged.state, 'ready');
  assert.equal(forged.state, 'error');
  assert.ok(
    !JSON.stringify(forged).includes('99999999'),
    'the fabricated number must never reach a card',
  );
});

test('THE FORGERY, mixed: one genuine slot and one forged slot renders the genuine one and marks the result incomplete', async () => {
  const res = await buildCards(
    readerInputs([
      await slot(cash('-1234.50'), realDevice.privateKey),
      await slot({ section: 'stock_value', rows: [{ companyGuid: GUID, asOf: AS_OF, stockGroup: 'W', closingValue: '-500000.00' }] }, serverKp.privateKey),
    ]),
  );
  assert.equal(res.state, 'ready');
  if (res.state !== 'ready') return;
  assert.equal(res.incomplete, true, 'a refused slot MUST mark the dashboard incomplete');
  assert.equal(res.companies[0]!.cashBank!.total.paise, 123450);
  assert.equal(res.companies[0]!.stock, undefined, 'the forged section must not render');
});

test('a roster that pins the deviceId but a DIFFERENT key does not rescue the forgery (no id-only trust)', async () => {
  const res = await buildCards({
    ...readerInputs([await slot(cash('-1.00'), serverKp.privateKey)]),
    // The server's key, correctly pinned for the WRONG device name.
    roster: [{ deviceId: 'dev_server', publicKey: serverKp.publicKey }],
  });
  assert.notEqual(res.state, 'ready');
});

// ================================================================== THE GATE

const RECOVERY_KEY = new Uint8Array(32).fill(3);
const realSheet = () => makeRecoverySheet(RECOVERY_KEY, 'Acme Traders', '2026-07-16');
const settle = () => new Promise((r) => setTimeout(r, 10));

/** `screen/phase`, or `done`. Same helper wizard-host.test.ts uses. */
function phase(s: WizardState): string {
  return s.screen === 'done' ? 'done' : `${s.screen}/${s.phase}`;
}

function hangingEffects(over: Partial<WizardHostEffects> = {}): WizardHostEffects {
  return {
    probeCompanies: async () => ({ ok: true, companies: [{ guid: 'guid-1', name: 'Acme Traders' }] }),
    generateIdentity: async () => ({
      publicKey: new Uint8Array(32).fill(1),
      secretKey: new Uint8Array(32).fill(2),
      publicKeyB64: Buffer.from(new Uint8Array(32).fill(1)).toString('base64'),
    }),
    // Never resolves: the machine SITS in `provisioning`, which is the phase that accepts
    // `provision_succeeded`. This is the window wizard-host.test.ts never opens.
    provision: () => new Promise(() => {}),
    completeSetup: () => new Promise(() => {}),
    recoveryQr: async () => 'data:image/png;base64,AAAA',
    printSheet: async () => {},
    ...over,
  };
}

test('THE GATE, AT THE PHASE THAT ACCEPTS IT: a forged provision_succeeded during provisioning is inert', async () => {
  const host = new WizardHostMain(hangingEffects());
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();
  assert.equal(phase(host.getState()), 'connectCloud/provisioning', 'precondition: parked in the vulnerable phase');

  // The pure machine WOULD take this transition. Only the host boundary stops it.
  const after = await host.sendFromRenderer({
    type: 'provision_succeeded',
    projectId: 'prj_EVIL',
    deploymentUrl: 'https://evil.example',
  });
  assert.equal(phase(after), 'connectCloud/provisioning');
  assert.ok(!JSON.stringify(after).includes('prj_EVIL'));
  assert.ok(!JSON.stringify(after).includes('evil.example'));
});

test('THE GATE, FULL JUMP: renderer forges provisioning + its own sheet + its own answers and never reaches done', async () => {
  let wrapCalled = 0;
  const host = new WizardHostMain(
    hangingEffects({
      completeSetup: async () => {
        wrapCalled++;
        return new Promise(() => {}) as never; // hang in `wrapping`
      },
    }),
  );
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();

  // 1. Skip provisioning.
  await host.sendFromRenderer({ type: 'provision_succeeded', projectId: 'prj_EVIL', deploymentUrl: 'https://evil.example' });
  // 2. Skip the wrap and deliver a sheet the RENDERER invented.
  const evil = makeRecoverySheet(new Uint8Array(32).fill(9), 'Evil', '2026-01-01');
  await host.sendFromRenderer({ type: 'passphrase_submitted', passphrase: 'a sensible passphrase', confirm: 'a sensible passphrase' });
  await settle();
  await host.sendFromRenderer({ type: 'sheet_ready', sheet: evil });
  await host.sendFromRenderer({ type: 'continue' });
  // 3. Answer the gate from the invented sheet.
  const after = await host.sendFromRenderer({
    type: 'verify_submitted',
    answers: [evil.words[3]!, evil.words[16]!],
  });

  assert.notEqual(after.screen, 'done', 'THE UNSKIPPABLE GATE WAS JUMPED');
  assert.equal(wrapCalled, 0, 'no real wrap ever ran, so `done` here would be a printed sheet that opens nothing');
  assert.ok(!JSON.stringify(after).includes(evil.words[3]!), "the renderer's invented sheet must never enter main-process state");
  // MEASURED, so nobody credits the wrong defence: this test still passes with
  // `validateRendererEvent` deleted. The jump dead-ends one layer deeper, at `runWrap`'s
  // `!this.cloud` guard — a forged `provision_succeeded` sets no CloudOutcome, so the wrap
  // refuses and the machine lands on `problem` instead of `wrapping`. That backstop is real but
  // UNDOCUMENTED (the file header credits the boundary alone). The two tests either side of this
  // one are the ones that isolate the boundary itself.
});

test('THE GATE: a forged sheet_ready during `wrapping` cannot replace the real sheet the driver is about to deliver', async () => {
  let release: ((s: unknown) => void) | undefined;
  const host = new WizardHostMain(
    hangingEffects({
      provision: async () => ({ projectId: 'prj_1', deploymentUrl: 'https://acme.vercel.app', tenantId: 'tn_1', bootstrapSecret: 'boot' }),
      completeSetup: () => new Promise((r) => { release = r as (s: unknown) => void; }) as never,
    }),
  );
  host.getState();
  await settle();
  await host.sendFromRenderer({ type: 'continue' });
  await settle();
  await host.sendFromRenderer({ type: 'token_pasted', token: 'tok' });
  await settle();
  await host.sendFromRenderer({ type: 'passphrase_submitted', passphrase: 'a sensible passphrase', confirm: 'a sensible passphrase' });
  await settle();
  assert.equal(phase(host.getState()), 'setPassphrase/wrapping');

  const evil = makeRecoverySheet(new Uint8Array(32).fill(9), 'Evil', '2026-01-01');
  await host.sendFromRenderer({ type: 'sheet_ready', sheet: evil });
  assert.equal(phase(host.getState()), 'setPassphrase/wrapping', 'still waiting on the REAL wrap');

  // The real sheet lands only from the driver, and it is the one the gate checks.
  release!(realSheet());
  await settle();
  const s = host.getState();
  assert.ok(s.screen === 'setPassphrase' && s.phase === 'sheet');
  if (s.screen === 'setPassphrase' && s.phase === 'sheet') {
    assert.deepEqual(s.sheet.words, realSheet().words);
  }
});

test('THE GATE: prototype pollution and oversized payloads through sendFromRenderer', async () => {
  const host = new WizardHostMain(hangingEffects());
  host.getState();
  await settle();

  await host.sendFromRenderer(JSON.parse('{"type":"continue","__proto__":{"polluted":"yes"}}'));
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined, 'Object.prototype was polluted');

  await host.sendFromRenderer({ type: 'select_company', guid: 'guid-1', constructor: { prototype: { x: 1 } } });
  await host.sendFromRenderer({ type: 'token_pasted', token: 'x'.repeat(100_000) });
  await host.sendFromRenderer({ type: 'verify_submitted', answers: new Array(10_000).fill('a') });
  assert.equal(({} as Record<string, unknown>)['polluted'], undefined);
});

// ================================================================== THE ROLLBACK MARK, AS A FILE

test('THE MARK AS A FILE: a dangling symlink reads as ENOENT, i.e. SILENTLY first-use', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mark-'));
  const store = new RosterMarkStore(dir);
  const idpk = Buffer.from(new Uint8Array(32).fill(7)).toString('base64');
  store.save(idpk, 9);
  assert.deepEqual(store.load(idpk), { kind: 'seen', highestVersionSeen: 9 });

  // Replace the mark with a symlink to nowhere.
  rmSync(join(dir, 'roster-mark.json'));
  symlinkSync(join(dir, 'does-not-exist'), join(dir, 'roster-mark.json'));

  // DOCUMENTED, NOT ENDORSED: readFileSync on a dangling symlink throws ENOENT, and ENOENT is
  // the one errno that means "first use". Rollback protection is off. This needs an attacker
  // with write access to userData — the same attacker who reads Tally's plaintext files
  // directly (ARCHITECTURE.md), so it is in the out-of-scope band, not a new hole. Pinned so
  // that nobody later claims this file is tamper-EVIDENT. It is not; deleting it does the same.
  assert.deepEqual(store.load(idpk), { kind: 'first-use' });
  rmSync(dir, { recursive: true, force: true });
});

test('THE MARK AS A FILE: a directory, and unreadable bytes, both fail CLOSED', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mark-'));
  const idpk = Buffer.from(new Uint8Array(32).fill(7)).toString('base64');
  mkdirSync(join(dir, 'roster-mark.json'));
  assert.throws(() => new RosterMarkStore(dir).load(idpk), /cannot be read|not valid JSON|malformed/);
  rmSync(dir, { recursive: true, force: true });

  const dir2 = mkdtempSync(join(tmpdir(), 'mark-'));
  writeFileSync(join(dir2, 'roster-mark.json'), '  not json');
  assert.throws(() => new RosterMarkStore(dir2).load(idpk), /RosterError|JSON|malformed/);
  rmSync(dir2, { recursive: true, force: true });
});

test('THE MARK: every hostile version shape is refused, and NaN never reaches a comparison', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mark-'));
  const store = new RosterMarkStore(dir);
  const idpk = Buffer.from(new Uint8Array(32).fill(7)).toString('base64');
  for (const v of ['NaN', 'null', '1.5', '-1', '0', '9007199254740993', '"5"', '{}', '[]', 'true', '1e999']) {
    writeFileSync(join(dir, 'roster-mark.json'), `{"v":1,"idPK":${JSON.stringify(idpk)},"highestVersionSeen":${v}}`);
    assert.throws(() => store.load(idpk), /not an integer|malformed|not valid JSON/, `version ${v} must be refused`);
  }
  for (const v of [NaN, Infinity, -Infinity, 1.5, -1, 0, 2 ** 53, '5' as unknown as number]) {
    assert.throws(() => store.save(idpk, v as number), /refusing/, `save(${String(v)}) must be refused`);
  }
  rmSync(dir, { recursive: true, force: true });
});

test('THE MARK: one identity\'s mark cannot be spent as another\'s, in either direction', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mark-'));
  const store = new RosterMarkStore(dir);
  const a = Buffer.from(new Uint8Array(32).fill(1)).toString('base64');
  const b = Buffer.from(new Uint8Array(32).fill(2)).toString('base64');
  store.save(a, 9);
  // B is a genuinely fresh reader; A's high mark must not gate it...
  assert.deepEqual(store.load(b), { kind: 'first-use' });
  // ...and B's low mark must not LOWER A's, which would be the rollback.
  store.save(b, 1);
  assert.deepEqual(store.load(b), { kind: 'seen', highestVersionSeen: 1 });
  // NOTE: A's mark is now GONE — the file holds one identity at a time. Reading A again is
  // first-use. Only reachable by re-provisioning a NEW identity and restoring the OLD wrapped
  // blob, which requires the old passphrase AND local write access. Pinned as known behaviour.
  assert.deepEqual(store.load(a), { kind: 'first-use' });
  rmSync(dir, { recursive: true, force: true });
});
