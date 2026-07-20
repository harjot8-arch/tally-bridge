import type { IsoDate, SectionPayload, WrappedKey } from '@tally-bridge/core';
import {
  generateIdentity,
  makeAad,
  sealSection,
  sodiumReady,
  toBase64,
  wrapIdentity,
  type DeviceRoster,
  type SignedEnvelope,
} from '@tally-bridge/crypto';
import { ROUTES } from '@tally-bridge/protocol';
import type { FetchLike, SnapshotRow } from '../src/data/api.ts';
import type { KV } from '../src/data/marks.ts';
import type { UnlockedSession } from '../src/data/unlock.ts';

/**
 * Test fixture: a REAL identity, a REAL device signing key, a REAL passphrase-wrapped bundle
 * (one Argon2id at production parameters — slow, paid once per file), and a hostile server's
 * own signing keypair. Mirrors the technique of apps/bridge/test/backend.adversary.test.ts:
 * the adversary computes everything it can actually compute — a fresh CEK sealed to the true
 * idPK, correct AAD, matching contentHash — and only the roster stands between it and a card.
 */

export const TENANT = 't_1';
export const DEVICE = 'dev_001';
export const AS_OF: IsoDate = '2026-07-16';
export const GUID = 'guid-acme';
export const PASSPHRASE = 'a sensible passphrase';

export interface Fixture {
  sodium: Awaited<ReturnType<typeof sodiumReady>>;
  identity: { publicKey: Uint8Array; secretKey: Uint8Array };
  idPkB64: string;
  /** The legitimate Bridge device's Ed25519 signing keypair. */
  device: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** The malicious server's OWN keypair. It knows idPK and the real deviceId. */
  server: { publicKey: Uint8Array; privateKey: Uint8Array };
  roster: DeviceRoster;
  rosterVersion: number;
  /** The passphrase wrap, roster sealed inside, as the server would store and serve it. */
  passBlob: WrappedKey;
  /** base64 of the auth token the passphrase derives — what a correct login presents. */
  authTokenB64: string;
}

export async function makeFixture(rosterVersion = 1): Promise<Fixture> {
  const sodium = await sodiumReady();
  const identity = await generateIdentity();
  const device = sodium.crypto_sign_keypair();
  const server = sodium.crypto_sign_keypair();
  const roster: DeviceRoster = [{ deviceId: DEVICE, publicKey: device.publicKey }];
  const wraps = await wrapIdentity(
    identity.secretKey,
    { version: rosterVersion, devices: roster },
    { passphrase: PASSPHRASE, recoveryKey: new Uint8Array(32).fill(7) },
  );
  return {
    sodium,
    identity,
    idPkB64: toBase64(identity.publicKey),
    device,
    server,
    roster,
    rosterVersion,
    passBlob: wraps.pass,
    authTokenB64: toBase64(wraps.authToken),
  };
}

/** Re-wrap the SAME identity at a different roster version (a legitimate roster change). */
export async function rewrapAtVersion(fx: Fixture, version: number): Promise<WrappedKey> {
  const wraps = await wrapIdentity(
    fx.identity.secretKey,
    { version, devices: fx.roster },
    { passphrase: PASSPHRASE, recoveryKey: new Uint8Array(32).fill(7) },
  );
  return wraps.pass;
}

export const cashPayload = (closing: string): SectionPayload => ({
  section: 'cash_bank',
  rows: [
    { companyGuid: GUID, asOf: AS_OF, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing },
  ],
});

export const companyPayload = (): SectionPayload => ({
  section: 'company',
  rows: [
    {
      companyGuid: GUID,
      name: 'Acme Traders',
      state: 'Gujarat',
      booksFrom: '2024-04-01',
      lastVoucherDate: AS_OF,
      tallyFlavour: 'prime',
      tallyVersion: '4.1',
    },
  ],
});

let seq = 0;

/** Seal one payload with the given signer and list it the way GET /api/snapshots would. */
export async function slotRow(
  fx: Fixture,
  payload: SectionPayload,
  signer: Uint8Array,
  over: Partial<{
    tenantId: string;
    deviceId: string;
    companyGuid: string;
    listedSection: string;
    aadSection: SectionPayload['section'];
    asOf: IsoDate;
    snapshotTs: number;
  }> = {},
): Promise<SnapshotRow> {
  const aad = makeAad({
    tenantId: over.tenantId ?? TENANT,
    deviceId: over.deviceId ?? DEVICE,
    companyGuid: over.companyGuid ?? GUID,
    section: over.aadSection ?? payload.section,
    asOf: over.asOf ?? AS_OF,
    snapshotTs: over.snapshotTs ?? 1_000_000,
    seq: ++seq,
  });
  const env: SignedEnvelope = await sealSection(payload, aad, fx.identity.publicKey, signer);
  return {
    companyGuid: over.companyGuid ?? GUID,
    section: (over.listedSection ?? aad.section) as SnapshotRow['section'],
    asOf: over.asOf ?? AS_OF,
    snapshotTs: over.snapshotTs ?? 1_000_000,
    seq,
    envelope: env,
  };
}

/** A ready-made UnlockedSession from the fixture, for read-path tests that skip Argon2id. */
export function sessionOf(fx: Fixture): UnlockedSession {
  return {
    tenantId: TENANT,
    identitySecretKey: fx.identity.secretKey,
    identityPublicKeyB64: fx.idPkB64,
    roster: fx.roster,
    rosterVersion: fx.rosterVersion,
    firstUse: false,
    persistentMemory: true,
  };
}

/* ------------------------------------------------------------------ fake server */

export interface FakeServerConfig {
  kdf?: unknown;
  wrappedKeys?: unknown;
  snapshots?: unknown;
  /** Force /api/login to answer this status regardless of the token. */
  loginStatus?: number;
  authTokenB64?: string;
}

/**
 * An in-process fake of the read API, honouring the `{ok, data}` body contract of
 * apps/server/src/router.ts. It answers with `Response` objects through the same `FetchLike`
 * seam the browser build injects real `fetch` through.
 */
export function fakeServer(fx: Fixture, cfg: FakeServerConfig = {}): FetchLike {
  const json = (status: number, body: unknown): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });

  return async (path, init) => {
    const method = init?.method ?? 'GET';
    const url = new URL(path, 'http://fake.local');

    if (url.pathname === ROUTES.prelogin.path && method === ROUTES.prelogin.method) {
      // The server copies login_credential.kdf from the pass blob itself; so does this fake.
      return json(200, { ok: true, data: { kdf: cfg.kdf ?? fx.passBlob.kdf } });
    }
    if (url.pathname === ROUTES.login.path && method === ROUTES.login.method) {
      if (cfg.loginStatus !== undefined) {
        return json(cfg.loginStatus, { ok: false, error: 'refused' });
      }
      const body = JSON.parse(String(init?.body)) as { tenantId?: string; authToken?: string };
      const expected = cfg.authTokenB64 ?? fx.authTokenB64;
      if (body.tenantId === TENANT && body.authToken === expected) {
        return json(200, { ok: true, data: {} });
      }
      return json(401, { ok: false, error: 'bad credentials' });
    }
    if (url.pathname === ROUTES.wrappedKeys.path && method === ROUTES.wrappedKeys.method) {
      return json(200, { ok: true, data: cfg.wrappedKeys ?? [fx.passBlob] });
    }
    if (url.pathname === ROUTES.snapshots.path && method === ROUTES.snapshots.method) {
      return json(200, { ok: true, data: cfg.snapshots ?? [] });
    }
    if (url.pathname === ROUTES.logout.path) {
      return json(200, { ok: true, data: {} });
    }
    return json(404, { ok: false, error: `no such route ${method} ${url.pathname}` });
  };
}

/* ------------------------------------------------------------------ storage fakes */

/** In-memory KV that mimics localStorageKV semantics but records every write. */
export function spyKV(): KV & { map: Map<string, string>; writes: string[] } {
  const map = new Map<string, string>();
  const writes: string[] = [];
  return {
    map,
    writes,
    get: (k) => map.get(k),
    set: (k, v) => {
      map.set(k, v);
      writes.push(k);
    },
    persistent: true,
  };
}
