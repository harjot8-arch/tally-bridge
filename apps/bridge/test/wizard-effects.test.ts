import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { WrappedKey } from '@tally-bridge/core';
import {
  KDF_INFO,
  deriveRoot,
  fromBase64,
  generateIdentity,
  hkdf,
  openIdentity,
} from '@tally-bridge/crypto';
import { ROUTES, verifyRequest } from '@tally-bridge/protocol';
import { createWizardEffects, type WizardEffectDeps } from '../src/main/wizard-effects.ts';
import { Keystore, type KeystoreBackend, type SafeStorageLike } from '../src/main/keystore.ts';
import { HumanError } from '../src/main/errors.ts';
import type { ProbeTransport } from '../src/main/detect.ts';

/**
 * completeSetup — the commit of onboarding, driven against a fake server.
 *
 * What is on trial here is the LAST gap between the desktop app and a usable web dashboard:
 * the Bridge must not only wrap the identity, it must PUT the pass + recovery wraps and the
 * login credential to /api/wrapped-keys — signed through the same Ed25519 device door as
 * /api/sync — or the server's wrapped_key table stays empty and no browser can ever log in.
 *
 * The assertions deliberately recompute the other side of every contract rather than trusting
 * this side's output: the signature is checked with verifyRequest against the key the register
 * call enrolled; the credential hash is re-derived from the uploaded pass wrap's OWN kdf params
 * exactly as a browser will after prelogin; the uploaded blobs are actually opened with the
 * passphrase and with the printed sheet's key.
 *
 * Argon2id is ~half a second per derive by design, so these tests are few and each one earns
 * its derives.
 */

const PASSPHRASE = 'Ramesh@1985';

interface Sent {
  path: string;
  method: string;
  headers: Record<string, string>;
  body: Uint8Array;
  bodyText: string;
}

function harness(opts?: {
  /** HTTP status per (path, 1-based call number). Default 200. */
  status?: (path: string, call: number) => number;
  /** Simulate DNS/offline/reset for a given (path, call). */
  networkFail?: (path: string, call: number) => boolean;
}) {
  const sent: Sent[] = [];
  /** Interleaved order of everything observable: `http:<path>` and `keystore:<key>`. */
  const events: string[] = [];
  const counts = new Map<string, number>();

  const fetchImpl = (async (url: URL | RequestInfo, init?: RequestInit) => {
    const path = new URL(String(url)).pathname;
    const call = (counts.get(path) ?? 0) + 1;
    counts.set(path, call);
    const raw = init?.body;
    const body =
      typeof raw === 'string' ? new TextEncoder().encode(raw) : new Uint8Array(raw as Uint8Array);
    sent.push({
      path,
      method: init?.method ?? 'GET',
      headers: { ...(init?.headers as Record<string, string>) },
      body,
      bodyText: new TextDecoder().decode(body),
    });
    events.push(`http:${path}`);
    if (opts?.networkFail?.(path, call)) throw new TypeError('fetch failed');
    return new Response('{}', { status: opts?.status?.(path, call) ?? 200 });
  }) as typeof fetch;

  const backendStore = new Map<string, Buffer>();
  const backend: KeystoreBackend = {
    read: (k) => backendStore.get(k),
    write: (k, v) => {
      events.push(`keystore:${k}`);
      backendStore.set(k, v);
    },
    delete: (k) => void backendStore.delete(k),
    has: (k) => backendStore.has(k),
  };
  const safe: SafeStorageLike = {
    isEncryptionAvailable: () => true,
    encryptString: (s) => Buffer.from('enc:' + s, 'utf8'),
    decryptString: (b) => b.toString('utf8').slice(4),
  };
  const keystore = new Keystore(safe, backend);

  const deps: WizardEffectDeps = {
    transport: {
      currentEncoding: 'utf-16le',
      detectEncoding: async () => undefined,
      request: async () => {
        throw new Error('completeSetup must not talk to Tally');
      },
    } as unknown as ProbeTransport,
    keystore,
    qrPngDataUrl: async () => 'data:image/png;base64,AA==',
    printHtml: async () => {},
    fetchImpl,
    now: () => Date.UTC(2026, 6, 17),
    loadDeployFiles: () => [],
  };

  return { effects: createWizardEffects(deps), sent, events, keystore, backendStore };
}

async function setupInput() {
  const identity = await generateIdentity();
  return {
    passphrase: PASSPHRASE,
    company: { guid: 'guid-1', name: 'Acme Traders' },
    identity: {
      publicKey: identity.publicKey,
      secretKey: identity.secretKey,
      publicKeyB64: Buffer.from(identity.publicKey).toString('base64'),
    },
    cloud: {
      projectId: 'prj_1',
      deploymentUrl: 'https://acme-dash.example',
      tenantId: 'tn_0011223344556677',
      bootstrapSecret: 'bootstrap-secret',
    },
  };
}

test('completeSetup uploads the pass + recovery wraps and the login credential through the device door', async () => {
  const h = harness();
  const input = await setupInput();
  const sheet = await h.effects.completeSetup(input);

  const registers = h.sent.filter((s) => s.path === ROUTES.register.path);
  const puts = h.sent.filter((s) => s.path === ROUTES.putWrappedKey.path);
  assert.equal(registers.length, 1);
  assert.equal(puts.length, 1, 'the wrapped keys must actually be uploaded');

  // Order: enrol -> upload -> keystore. The upload needs the enrolled device (device door);
  // the keystore write wakes the sync cycle and must come only when the dashboard can log in.
  const putAt = h.events.indexOf(`http:${ROUTES.putWrappedKey.path}`);
  const firstKeystoreWrite = h.events.findIndex((e) => e.startsWith('keystore:'));
  assert.ok(putAt > h.events.indexOf(`http:${ROUTES.register.path}`), 'enrolment precedes the upload');
  assert.ok(firstKeystoreWrite > putAt, 'the keystore is written only after the upload succeeded');

  const put = puts[0]!;
  assert.equal(put.method, ROUTES.putWrappedKey.method);

  // The signature verifies EXACTLY the way apps/server verifies it: verifyRequest over the
  // shared route constant (the path is inside the signed bytes), the sent body bytes, and the
  // public key the register call enrolled. A literal path here, or different bytes signed than
  // sent, fails this — the same way it would 401 in production.
  const reg = JSON.parse(registers[0]!.bodyText) as { deviceId: string; publicKey: string };
  const verdict = await verifyRequest(
    put.headers,
    { method: ROUTES.putWrappedKey.method, path: ROUTES.putWrappedKey.path, body: put.body },
    {
      lookupDevice: async (id) =>
        id === reg.deviceId
          ? { publicKey: new Uint8Array(Buffer.from(reg.publicKey, 'base64')), revoked: false }
          : undefined,
      rememberNonce: async () => true,
      admit: async () => ({ ok: true }),
      now: () => Date.now(),
    },
  );
  assert.ok(verdict.ok, `the device signature must verify: ${JSON.stringify(verdict)}`);

  // Body shape: what validatePutBody (apps/server/src/auth.ts) accepts and nothing looser.
  const parsed = JSON.parse(put.bodyText) as { keys: WrappedKey[]; authTokenHash: string };
  assert.deepEqual(parsed.keys.map((k) => k.kind).sort(), ['pass', 'recovery']);
  const pass = parsed.keys.find((k) => k.kind === 'pass')!;
  const recovery = parsed.keys.find((k) => k.kind === 'recovery')!;
  assert.ok(pass.kdf, 'the pass wrap must carry kdf params — prelogin serves this salt');
  assert.equal(recovery.kdf, undefined, 'kdf must be present on pass EXACTLY, absent elsewhere');

  // The login credential, recomputed the way a browser will at login: Argon2id root from the
  // uploaded pass wrap's OWN params, HKDF under the shared auth label, SHA-256, base64.
  const root = await deriveRoot(PASSPHRASE, pass.kdf!);
  const authToken = await hkdf(root, KDF_INFO.auth);
  assert.equal(
    parsed.authTokenHash,
    createHash('sha256').update(authToken).digest('base64'),
    'login_credential must match what the browser derives, or login fails for every owner',
  );

  // What was uploaded actually opens with the passphrase, and pins the enrolled device.
  const opened = await openIdentity(pass, { kind: 'pass', passphrase: PASSPHRASE }, { kind: 'first-use' });
  assert.deepEqual(opened.identitySecretKey, input.identity.secretKey);
  assert.deepEqual(
    opened.roster.map((d) => d.deviceId),
    [reg.deviceId],
    'the sealed roster names the device that was enrolled',
  );

  // And the recovery wrap opens with the key the printed sheet carries.
  const viaSheet = await openIdentity(
    recovery,
    { kind: 'recovery', recoveryKey: fromBase64(sheet.keyBase64) },
    { kind: 'first-use' },
  );
  assert.deepEqual(viaSheet.identitySecretKey, input.identity.secretKey);

  // The local unlock blob and the uploaded pass wrap are ONE value, so the salt prelogin
  // serves and the salt the local blob derives under cannot drift.
  assert.equal(h.keystore.getWrappedIdentityForPassphrase(), JSON.stringify(pass));
  assert.equal(h.keystore.isProvisioned(), true);
  assert.equal(h.keystore.getDeviceId(), reg.deviceId);
});

test('a failed upload aborts setup BEFORE the keystore write — no syncing Bridge over a dashboard with no login', async () => {
  const h = harness({ status: (path) => (path === ROUTES.putWrappedKey.path ? 500 : 200) });
  await assert.rejects(
    async () => h.effects.completeSetup(await setupInput()),
    (e: unknown) => {
      assert.ok(e instanceof HumanError, 'the owner sees one plain sentence');
      assert.doesNotMatch((e as Error).message, /\d{3}|status|http/i, 'never a status code');
      return true;
    },
  );
  // isProvisioned() is what wakes the sync cycle; it must still be false, and nothing at all
  // may have been persisted — a half-written keystore is a half-truth on the next launch.
  assert.equal(h.keystore.isProvisioned(), false);
  assert.equal(h.backendStore.size, 0, 'nothing was persisted');
});

test('retry after a failed upload reuses the enrolled device — the one-shot bootstrap door is knocked once', async () => {
  const h = harness({
    status: (path, call) => (path === ROUTES.putWrappedKey.path && call === 1 ? 503 : 200),
  });
  const input = await setupInput();
  await assert.rejects(() => h.effects.completeSetup(input), HumanError);
  const sheet = await h.effects.completeSetup(input);
  assert.equal(sheet.words.length, 24);

  const registers = h.sent.filter((s) => s.path === ROUTES.register.path);
  const puts = h.sent.filter((s) => s.path === ROUTES.putWrappedKey.path);
  assert.equal(registers.length, 1, 'a retry must not knock on the consumed bootstrap door again');
  assert.equal(puts.length, 2);
  assert.equal(
    puts[0]!.headers['x-tb-device'],
    puts[1]!.headers['x-tb-device'],
    'the same device signs both attempts',
  );
  assert.equal(h.keystore.isProvisioned(), true);

  // The run that succeeded is self-consistent: the pass wrap it uploaded is the pass wrap the
  // keystore holds (a retry re-wraps, so the failed attempt's blobs must not survive anywhere).
  const parsed = JSON.parse(puts[1]!.bodyText) as { keys: WrappedKey[] };
  const pass = parsed.keys.find((k) => k.kind === 'pass')!;
  assert.equal(h.keystore.getWrappedIdentityForPassphrase(), JSON.stringify(pass));
});

test('a network failure during the upload is one sentence, and the keystore stays untouched', async () => {
  const h = harness({ networkFail: (path) => path === ROUTES.putWrappedKey.path });
  await assert.rejects(
    async () => h.effects.completeSetup(await setupInput()),
    (e: unknown) => {
      assert.ok(e instanceof HumanError);
      assert.match((e as Error).message, /internet/i, 'names the thing the owner can check');
      return true;
    },
  );
  assert.equal(h.keystore.isProvisioned(), false);
});
