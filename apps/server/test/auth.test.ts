import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  KDF_INFO,
  deriveRoot,
  generateIdentity,
  hkdf,
  randomSalt,
  unwrapWithPassphrase,
  wrapUnderPassphrase,
} from '@tally-bridge/crypto';
import {
  MAX_UPLOADS_PER_HOUR_PER_DEVICE,
  ROUTES,
  generateDeviceKeypair,
  signRequest,
} from '@tally-bridge/protocol';
import type { KdfParams, WrappedKey } from '@tally-bridge/core';
import {
  AUTH_KDF_INFO,
  MAX_LOGIN_ATTEMPTS_PER_HOUR,
  MAX_LOGIN_ATTEMPTS_PER_IP_PER_HOUR,
  MAX_LOGIN_BODY_BYTES,
  MAX_PRELOGIN_PER_HOUR,
  MAX_PRELOGIN_PER_IP_PER_HOUR,
  SESSION_ABSOLUTE_TTL_SECONDS,
  SESSION_COOKIE_NAME,
  SESSION_IDLE_TIMEOUT_SECONDS,
  handleLogin,
  handleLogout,
  handlePrelogin,
  handlePutWrappedKey,
  hashSessionToken,
  sessionTokenFromHeaders,
  type AuthDeps,
  type PutWrappedKeyDeps,
} from '../src/auth.ts';
import { splitStatements } from '../src/migrate.ts';
import {
  authDepsFromSql,
  requireSessionFromSql,
  wrappedKeyDepsFromSql,
  type Row,
  type Sql,
} from '../src/db.ts';

/**
 * The session door, end to end: prelogin -> login -> session -> logout, plus the device-door
 * write (PUT /api/wrapped-keys) that makes any of it usable.
 *
 * Every security test here was MUTATION-CHECKED: the named defence was deleted or inverted in
 * src, the test observed red, and the change reverted. The table lives in the delivery report;
 * the tests that could not be made to fail were deleted rather than kept as decoration. The one
 * property tests cannot observe is CONSTANT-TIMENESS itself (a unit test cannot measure a
 * timing distribution meaningfully); what is tested is the functional contract around the
 * compare, and the mutation for "compare always true" is caught by the wrong-token test.
 */

const NOW = 1_752_600_000_000;
const TENANT = 'tnt_1';
const DEVICE = 'dev_1';
const HOUR_MS = 3_600_000;

const sha256 = (data: Uint8Array | string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(data).digest());
const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

const validKdf = (): KdfParams => ({
  v: 1,
  kdf: 'argon2id',
  m: 64 * 1024 * 1024,
  t: 3,
  p: 1,
  salt: b64(new Uint8Array(16).fill(7)),
});

/** A synthetic wrapped key: structurally valid, cryptographically meaningless. Validation-path
 * tests need shape, not unwrappability; the real crypto is exercised in the E2E test. */
const syntheticKey = (kind: WrappedKey['kind'], kdf?: KdfParams): WrappedKey => {
  const base: WrappedKey = {
    v: 2,
    kind,
    nonce: b64(new Uint8Array(24).fill(1)),
    ciphertext: b64(new Uint8Array(64).fill(2)),
  };
  if (kdf) base.kdf = kdf;
  return base;
};

/* ------------------------------------------------------------------ *
 * Handler-level AuthDeps fake
 * ------------------------------------------------------------------ */

function fakeAuthDeps(over: Partial<AuthDeps> = {}) {
  const credentials = new Map<string, { tokenHash: Uint8Array; kdf: KdfParams }>();
  /** base64(sha256(sessionToken)) -> tenantId. The KEY BEING THE HASH is itself under test. */
  const sessions = new Map<string, string>();
  const attempts = new Map<string, number>();

  const deps: AuthDeps = {
    deploymentSecret: async () => 'a-fixed-test-deployment-secret',
    getLoginCredential: async (tenantId) => credentials.get(tenantId),
    reserveAuthAttempt: async (key) => {
      const n = (attempts.get(key) ?? 0) + 1;
      attempts.set(key, n);
      return n;
    },
    createSession: async (tokenHash, tenantId) => {
      sessions.set(b64(tokenHash), tenantId);
    },
    deleteSession: async (tokenHash) => sessions.delete(b64(tokenHash)),
    ...over,
  };
  return { deps, credentials, sessions, attempts };
}

function enrolSyntheticCredential(
  credentials: Map<string, { tokenHash: Uint8Array; kdf: KdfParams }>,
  tenantId = TENANT,
) {
  const authToken = new Uint8Array(32).fill(9);
  credentials.set(tenantId, { tokenHash: sha256(authToken), kdf: validKdf() });
  return { authToken };
}

const loginBody = (tenantId: unknown, authToken: unknown): Uint8Array =>
  new TextEncoder().encode(JSON.stringify({ tenantId, authToken }));

const cookieTokenOf = (setCookie: string | undefined): string => {
  const m = new RegExp(`${SESSION_COOKIE_NAME}=([A-Za-z0-9_-]{43})`).exec(setCookie ?? '');
  assert.ok(m, `no session token in Set-Cookie: ${String(setCookie)}`);
  return m![1]!;
};

const dataOf = <T>(res: { body: { ok: true; data: T } | { ok: false; error: string } }): T => {
  assert.equal(res.body.ok, true, `expected ok, got ${JSON.stringify(res.body)}`);
  return (res.body as { ok: true; data: T }).data;
};

/* ------------------------------------------------------------------ *
 * Prelogin
 * ------------------------------------------------------------------ */

test('prelogin: a real tenant receives exactly its stored KDF params', async () => {
  const { deps, credentials } = fakeAuthDeps();
  enrolSyntheticCredential(credentials);

  const res = await handlePrelogin(TENANT, deps, '1.1.1.1');
  assert.equal(res.status, 200);
  assert.deepEqual(dataOf(res).kdf, credentials.get(TENANT)!.kdf);
});

test('prelogin: an unknown tenant gets a DETERMINISTIC decoy shaped like a real answer', async () => {
  const { deps, credentials } = fakeAuthDeps();
  enrolSyntheticCredential(credentials);

  const a = await handlePrelogin('tnt_ghost', deps, '1.1.1.1');
  const b = await handlePrelogin('tnt_ghost', deps, '2.2.2.2');
  const real = await handlePrelogin(TENANT, deps, '3.3.3.3');
  const other = await handlePrelogin('tnt_ghost2', deps, '4.4.4.4');

  // Same status, and both bodies carry the identical field set — no oracle in the shape.
  assert.equal(a.status, real.status);
  const [ka, kb, kReal, kOther] = [dataOf(a).kdf, dataOf(b).kdf, dataOf(real).kdf, dataOf(other).kdf];
  assert.deepEqual(Object.keys(ka).sort(), Object.keys(kReal).sort());

  // Deterministic across calls (a wobbling salt is detected in two requests)...
  assert.deepEqual(ka, kb);
  // ...and per-tenant, so a stable answer for one name says nothing about another.
  assert.notEqual(ka.salt, kOther.salt);

  // Cost params identical to a real credential's — today all real credentials carry the
  // shipped defaults, so any difference would be the oracle.
  assert.equal(ka.m, kReal.m);
  assert.equal(ka.t, kReal.t);

  // The decoy salt is the length libsodium's Argon2id actually takes — checked against a REAL
  // randomSalt() rather than a remembered constant.
  const realSalt = await randomSalt();
  assert.equal(Buffer.from(ka.salt, 'base64').length, realSalt.length);
});

test('prelogin: per-IP and global rate caps, refusing the (cap+1)th attempt', async () => {
  const { deps } = fakeAuthDeps();

  for (let i = 0; i < MAX_PRELOGIN_PER_IP_PER_HOUR; i++) {
    assert.equal((await handlePrelogin(TENANT, deps, '9.9.9.9')).status, 200);
  }
  assert.equal((await handlePrelogin(TENANT, deps, '9.9.9.9')).status, 429);
  // A different source is a different bucket — the cap is per IP, not per tenant.
  assert.equal((await handlePrelogin(TENANT, deps, '8.8.8.8')).status, 200);

  // The global bucket catches what per-IP buckets cannot: many sources, one target.
  const { deps: d2 } = fakeAuthDeps();
  for (let i = 0; i < MAX_PRELOGIN_PER_HOUR; i++) {
    const r = await handlePrelogin(TENANT, d2, `10.0.${Math.floor(i / 250)}.${i % 250}`);
    assert.notEqual(r.status, 429, `refused at ${i} of ${MAX_PRELOGIN_PER_HOUR}`);
  }
  assert.equal((await handlePrelogin(TENANT, d2, '99.99.99.99')).status, 429);
});

test('prelogin: a malformed tenant id is 400 and spends nothing', async () => {
  const { deps, attempts } = fakeAuthDeps();
  for (const bad of [undefined, '', 42, {}, 'x'.repeat(201)]) {
    assert.equal((await handlePrelogin(bad, deps, '1.1.1.1')).status, 400);
  }
  assert.equal(attempts.size, 0, 'shape validation must come before the meter');
});

test('prelogin: a missing deployment secret is a UNIFORM 503 — known and unknown tenant alike', async () => {
  const { deps, credentials } = fakeAuthDeps({ deploymentSecret: async () => undefined });
  enrolSyntheticCredential(credentials);

  const known = await handlePrelogin(TENANT, deps, '1.1.1.1');
  const unknown = await handlePrelogin('tnt_ghost', deps, '1.1.1.1');
  assert.equal(known.status, 503);
  // Identical answers, or the degraded mode is itself the existence oracle.
  assert.deepEqual(known, unknown);
});

test('prelogin: an unreadable attempt counter fails CLOSED', async () => {
  const { deps } = fakeAuthDeps({ reserveAuthAttempt: async () => Number.NaN });
  const res = await handlePrelogin(TENANT, deps, '1.1.1.1');
  assert.equal(res.status, 400);
});

/* ------------------------------------------------------------------ *
 * Login
 * ------------------------------------------------------------------ */

test('login: the right token mints a session and a fully-attributed cookie', async () => {
  const { deps, credentials, sessions } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);

  const res = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  assert.equal(res.status, 200);
  assert.equal(dataOf(res).tenantId, TENANT);

  const setCookie = res.setCookie!;
  const token = cookieTokenOf(setCookie);
  // Every attribute is load-bearing; see sessionCookie() for what each one buys.
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Path=\//);
  assert.match(setCookie, new RegExp(`Max-Age=${SESSION_ABSOLUTE_TTL_SECONDS}`));

  // THE ROW HOLDS THE HASH, NEVER THE TOKEN. A session-table dump must not mint cookies.
  assert.equal(sessions.size, 1);
  const storedKey = [...sessions.keys()][0]!;
  assert.notEqual(storedKey, token);
  assert.ok(!storedKey.includes(token));
  assert.equal(storedKey, b64(sha256(token)));
  assert.equal(sessions.get(storedKey), TENANT);
});

test('login: two logins mint two DIFFERENT tokens (CSPRNG, not derivation)', async () => {
  const { deps, credentials } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);
  const r1 = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  const r2 = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  assert.notEqual(cookieTokenOf(r1.setCookie), cookieTokenOf(r2.setCookie));
});

test('login: wrong token and unknown tenant are INDISTINGUISHABLE, and neither mints a session', async () => {
  const { deps, credentials, sessions } = fakeAuthDeps();
  enrolSyntheticCredential(credentials);

  const wrongToken = await handleLogin(loginBody(TENANT, b64(new Uint8Array(32).fill(8))), deps, '1.1.1.1');
  const wrongTenant = await handleLogin(loginBody('tnt_ghost', b64(new Uint8Array(32).fill(9))), deps, '1.1.1.1');

  assert.equal(wrongToken.status, 401);
  // Identical status AND body, or this endpoint enumerates tenants.
  assert.deepEqual(wrongToken, wrongTenant);
  assert.equal(wrongToken.setCookie, undefined);
  assert.equal(sessions.size, 0);
});

test('login: a corrupt stored hash (wrong length) reads as invalid credentials, not as a 500', async () => {
  const { deps, credentials } = fakeAuthDeps();
  credentials.set(TENANT, { tokenHash: new Uint8Array(31), kdf: validKdf() });
  const res = await handleLogin(loginBody(TENANT, b64(new Uint8Array(32))), deps, '1.1.1.1');
  assert.equal(res.status, 401);
});

test('login: the per-IP cap holds even against the CORRECT token', async () => {
  const { deps, credentials } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);

  for (let i = 0; i < MAX_LOGIN_ATTEMPTS_PER_IP_PER_HOUR; i++) {
    assert.equal((await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1')).status, 200);
  }
  const refused = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  assert.equal(refused.status, 429);
});

test('login: the GLOBAL cap catches a distributed grind that rotates IPs', async () => {
  const { deps, credentials } = fakeAuthDeps();
  enrolSyntheticCredential(credentials);

  for (let i = 0; i < MAX_LOGIN_ATTEMPTS_PER_HOUR; i++) {
    // A distinct wrong guess per attempt: varying first byte, zero tail — the enrolled token
    // is all-9s, so no guess ever collides with it.
    const guess = new Uint8Array(32);
    guess[0] = i;
    const r = await handleLogin(
      loginBody(TENANT, b64(guess)),
      deps,
      `10.0.${Math.floor(i / 9)}.${i % 9}`, // never reaches any per-IP cap
    );
    assert.equal(r.status, 401, `attempt ${i} should fail auth, not the cap`);
  }
  const refused = await handleLogin(loginBody(TENANT, b64(new Uint8Array(32))), deps, '172.16.0.1');
  assert.equal(refused.status, 429);
});

test('login: attempts are metered BEFORE parsing — malformed floods spend their own budget', async () => {
  const { deps, attempts } = fakeAuthDeps();
  await handleLogin(new TextEncoder().encode('{not json'), deps, '1.1.1.1');
  assert.ok((attempts.get('login:ip:1.1.1.1') ?? 0) >= 1, 'a malformed body was not metered');
});

test('login: an oversized body is 413 and is NOT metered (size is checked first)', async () => {
  const { deps, attempts } = fakeAuthDeps();
  const res = await handleLogin(new Uint8Array(MAX_LOGIN_BODY_BYTES + 1), deps, '1.1.1.1');
  assert.equal(res.status, 413);
  assert.equal(attempts.size, 0);
});

test('login: malformed inputs are each a 400, never a 500 and never a session', async () => {
  const { deps, sessions, credentials } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);
  const cases: Uint8Array[] = [
    new TextEncoder().encode('null'),
    new TextEncoder().encode('[1,2]'),
    loginBody(undefined, b64(authToken)),
    loginBody(TENANT, undefined),
    loginBody(TENANT, 'not-base64!!'),
    loginBody(TENANT, b64(new Uint8Array(31))), // wrong length
    loginBody(TENANT, b64(new Uint8Array(33))),
  ];
  for (const body of cases) {
    const res = await handleLogin(body, deps, '1.1.1.1');
    assert.equal(res.status, 400, new TextDecoder().decode(body));
  }
  assert.equal(sessions.size, 0);
});

test('login: an unreadable attempt counter fails CLOSED even for the correct token', async () => {
  const { credentials } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);
  const { deps } = fakeAuthDeps({
    getLoginCredential: async () => credentials.get(TENANT),
    reserveAuthAttempt: async () => Number.NaN,
  });
  const res = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  assert.equal(res.status, 400);
});

/* ------------------------------------------------------------------ *
 * Logout
 * ------------------------------------------------------------------ */

test('logout: destroys the session row server-side, not just the cookie', async () => {
  const { deps, credentials, sessions } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);

  const login = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  const token = cookieTokenOf(login.setCookie);
  assert.equal(sessions.size, 1);

  const res = await handleLogout({ cookie: `${SESSION_COOKIE_NAME}=${token}` }, deps);
  assert.equal(res.status, 200);
  // The cleared cookie is courtesy; the DELETE is the logout.
  assert.match(res.setCookie ?? '', /Max-Age=0/);
  assert.equal(sessions.size, 0, 'the session row survived logout — a copied token still works');
});

test('logout: without a session cookie is 401; a second logout is idempotent 200', async () => {
  const { deps, credentials, sessions } = fakeAuthDeps();
  const { authToken } = enrolSyntheticCredential(credentials);
  const login = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  const cookie = { cookie: `${SESSION_COOKIE_NAME}=${cookieTokenOf(login.setCookie)}` };

  assert.equal((await handleLogout({}, deps)).status, 401);
  assert.equal((await handleLogout(cookie, deps)).status, 200);
  assert.equal((await handleLogout(cookie, deps)).status, 200, 'second click must not be an error');
  assert.equal(sessions.size, 0);
});

/* ------------------------------------------------------------------ *
 * Cookie parsing
 * ------------------------------------------------------------------ */

test('sessionTokenFromHeaders: extracts among other cookies; rejects every malformed shape', () => {
  const token = 'A'.repeat(43);
  assert.equal(
    sessionTokenFromHeaders({ cookie: `theme=dark; ${SESSION_COOKIE_NAME}=${token}; lang=en` }),
    token,
  );
  assert.equal(sessionTokenFromHeaders({}), undefined);
  assert.equal(sessionTokenFromHeaders({ cookie: '' }), undefined);
  assert.equal(sessionTokenFromHeaders({ cookie: `${SESSION_COOKIE_NAME}=` }), undefined);
  assert.equal(sessionTokenFromHeaders({ cookie: `${SESSION_COOKIE_NAME}=${'A'.repeat(42)}` }), undefined);
  assert.equal(sessionTokenFromHeaders({ cookie: `${SESSION_COOKIE_NAME}=${'A'.repeat(44)}` }), undefined);
  assert.equal(sessionTokenFromHeaders({ cookie: `${SESSION_COOKIE_NAME}=${'A'.repeat(42)}+` }), undefined);
  // A megabyte of cookie is a parse-cost DoS on an unauthenticated path; refused outright.
  assert.equal(
    sessionTokenFromHeaders({ cookie: `x=${'a'.repeat(10_000)}; ${SESSION_COOKIE_NAME}=${token}` }),
    undefined,
  );
});

/* ------------------------------------------------------------------ *
 * requireSessionFromSql — the real RequireSession
 * ------------------------------------------------------------------ */

interface SessionRow {
  tenant: string;
  expiresAt: number;
  lastSeenAt: number;
}

/**
 * A fake Sql for the session/auth tables, with a controllable clock.
 *
 * CONDITION-SENSITIVE ON PURPOSE: the UPDATE applies the expiry and idle filters only if the
 * corresponding predicate is present in the SQL text. A mutation that deletes `expires_at >`
 * from db.ts therefore admits the expired session HERE and turns the expiry test red — instead
 * of merely failing to pattern-match and passing by accident.
 */
function fakeSessionSql() {
  let clock = NOW;
  const sessions = new Map<string, SessionRow>();
  const credentials = new Map<string, { tokenHashB64: string; kdf: KdfParams }>();
  const wrappedKeys = new Map<string, { kind: string; blob: WrappedKey }>();
  const loginCreds = new Map<string, { tokenHashB64: string; kdf: KdfParams }>();
  const attempts = new Map<string, number>();
  const queries: Array<{ text: string; params: unknown[] }> = [];
  let failNext: string | undefined;

  const sql: Sql = async (strings, ...params) => {
    const text = strings.join(' $? ').replace(/\s+/g, ' ').trim();
    queries.push({ text, params });
    if (failNext && text.includes(failNext)) {
      failNext = undefined;
      throw new Error('connection terminated unexpectedly');
    }

    if (/UPDATE session/i.test(text)) {
      const [hashB64, idleSecs] = params;
      const row = sessions.get(String(hashB64));
      if (!row) return [];
      if (text.includes('expires_at >') && !(row.expiresAt > clock)) return [];
      if (
        /last_seen_at >/.test(text) &&
        !(row.lastSeenAt > clock - Number(idleSecs) * 1000)
      ) {
        return [];
      }
      if (/SET last_seen_at/i.test(text)) row.lastSeenAt = clock;
      return [{ tenant_id: row.tenant }];
    }

    if (/INSERT INTO session/i.test(text)) {
      // Param order pinned by db.ts: gc idle, hash, tenant, ttl.
      const [idleSecs, hashB64, tenantId, ttlSecs] = params;
      if (text.includes('DELETE FROM session')) {
        for (const [k, r] of [...sessions]) {
          if (r.expiresAt < clock || r.lastSeenAt < clock - Number(idleSecs) * 1000) {
            sessions.delete(k);
          }
        }
      }
      sessions.set(String(hashB64), {
        tenant: String(tenantId),
        expiresAt: clock + Number(ttlSecs) * 1000,
        lastSeenAt: clock,
      });
      return [];
    }

    if (/DELETE FROM session/i.test(text)) {
      const [hashB64] = params;
      const row = sessions.get(String(hashB64));
      sessions.delete(String(hashB64));
      return row ? [{ tenant_id: row.tenant }] : [];
    }

    if (/FROM login_credential/i.test(text)) {
      const r = loginCreds.get(String(params[0]));
      return r ? [{ token_hash_b64: r.tokenHashB64, kdf: r.kdf }] : [];
    }

    if (/INSERT INTO login_credential/i.test(text)) {
      const [tenantId, hashB64, kdfJson] = params;
      loginCreds.set(String(tenantId), {
        tokenHashB64: String(hashB64),
        kdf: JSON.parse(String(kdfJson)) as KdfParams,
      });
      return [];
    }

    if (/FROM deployment_secret/i.test(text)) {
      return [{ secret: 'a-fixed-test-deployment-secret' }];
    }

    if (/INSERT INTO auth_window/i.test(text)) {
      // gc key, retention, insert key, sum key, window — every key must be the same bucket.
      const keys = params.filter((p) => typeof p === 'string');
      assert.ok(keys.length >= 3);
      assert.ok(keys.every((k) => k === keys[0]), 'sweep, upsert and sum must target one bucket');
      const key = String(keys[0]);
      const n = (attempts.get(key) ?? 0) + 1;
      attempts.set(key, n);
      // BIGINT arrives as a string from pg's parser; model that.
      return [{ attempts_in_window: String(n) }];
    }

    if (/INSERT INTO wrapped_key/i.test(text)) {
      const [tenantId, kind, blobJson] = params;
      wrappedKeys.set(`${String(tenantId)}|${String(kind)}`, {
        kind: String(kind),
        blob: JSON.parse(String(blobJson)) as WrappedKey,
      });
      return [];
    }

    if (/FROM wrapped_key/i.test(text)) {
      return [...wrappedKeys.entries()]
        .filter(([k]) => k.startsWith(`${String(params[0])}|`))
        .map(([, v]) => ({ kind: v.kind, blob: v.blob, updated_at: new Date(clock) })) as Row[];
    }

    throw new Error(`fakeSessionSql: unhandled query: ${text}`);
  };

  return {
    sql,
    sessions,
    credentials,
    loginCreds,
    wrappedKeys,
    queries,
    advance: (ms: number) => {
      clock += ms;
    },
    failOn: (fragment: string) => {
      failNext = fragment;
    },
  };
}

function seedSession(f: ReturnType<typeof fakeSessionSql>, token: string, tenant = TENANT) {
  f.sessions.set(b64(hashSessionToken(token)), {
    tenant,
    expiresAt: NOW + SESSION_ABSOLUTE_TTL_SECONDS * 1000,
    lastSeenAt: NOW,
  });
}

const TOKEN = 'T'.repeat(43);
const COOKIE = { cookie: `${SESSION_COOKIE_NAME}=${TOKEN}` };

test('session: a valid cookie resolves to its tenant, by hash lookup', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN);
  const require = requireSessionFromSql(f.sql);
  assert.equal(await require(COOKIE), TENANT);
  // The query carried the HASH, never the raw token.
  const q = f.queries.find((q) => /UPDATE session/.test(q.text))!;
  assert.ok(!JSON.stringify(q.params).includes(TOKEN), 'the raw session token reached the database');
});

test('session: absolute expiry ends it, whatever the activity', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN);
  const require = requireSessionFromSql(f.sql);
  f.advance(SESSION_ABSOLUTE_TTL_SECONDS * 1000 + 1);
  assert.equal(await require(COOKIE), undefined);
});

test('session: the idle timeout ends it, and activity SLIDES it', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN);
  const require = requireSessionFromSql(f.sql);

  // 20h idle, touch, 20h idle again: alive both times because the first touch slid the window.
  f.advance(20 * HOUR_MS);
  assert.equal(await require(COOKIE), TENANT);
  f.advance(20 * HOUR_MS);
  assert.equal(await require(COOKIE), TENANT);

  // 25h with no touch: dead. (Same clock arithmetic as the two hops above — only the absence
  // of the intermediate touch differs, which is exactly the sliding property.)
  const f2 = fakeSessionSql();
  seedSession(f2, TOKEN);
  f2.advance(SESSION_IDLE_TIMEOUT_SECONDS * 1000 + HOUR_MS);
  assert.equal(await requireSessionFromSql(f2.sql)(COOKIE), undefined);
});

test('session: no cookie, malformed cookie, unknown or tampered token — undefined every time', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN);
  const require = requireSessionFromSql(f.sql);

  assert.equal(await require({}), undefined);
  assert.equal(await require({ cookie: 'theme=dark' }), undefined);
  assert.equal(await require({ cookie: `${SESSION_COOKIE_NAME}=short` }), undefined);
  // One flipped character: hashes elsewhere, matches nothing.
  assert.equal(await require({ cookie: `${SESSION_COOKIE_NAME}=${'U' + TOKEN.slice(1)}` }), undefined);
  // A malformed cookie must not even reach the database.
  const before = f.queries.length;
  await require({ cookie: `${SESSION_COOKIE_NAME}=!!!` });
  assert.equal(f.queries.length, before);
});

test('session: a client-settable tenant header is NEVER the tenant source', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN, TENANT);
  const require = requireSessionFromSql(f.sql);

  // No cookie + a confident header: nothing.
  assert.equal(await require({ 'x-tenant-id': 'tnt_evil', 'x-tenant': 'tnt_evil' }), undefined);
  // Valid cookie + a lying header: the SESSION's tenant, not the header's.
  assert.equal(await require({ ...COOKIE, 'x-tenant-id': 'tnt_evil' }), TENANT);
});

test('session: a database failure is undefined — a 401, never a 500 (obligation 2)', async () => {
  const f = fakeSessionSql();
  seedSession(f, TOKEN);
  f.failOn('UPDATE session');
  // Must resolve, not reject: a throw here becomes a 500 in four different read handlers.
  assert.equal(await requireSessionFromSql(f.sql)(COOKIE), undefined);
});

test('session: login -> read -> logout, at the SQL layer — logout revokes server-side', async () => {
  const f = fakeSessionSql();
  const authToken = new Uint8Array(32).fill(5);
  f.loginCreds.set(TENANT, { tokenHashB64: b64(sha256(authToken)), kdf: validKdf() });

  const deps = authDepsFromSql(f.sql);
  const login = await handleLogin(loginBody(TENANT, b64(authToken)), deps, '1.1.1.1');
  assert.equal(login.status, 200);
  const cookie = { cookie: `${SESSION_COOKIE_NAME}=${cookieTokenOf(login.setCookie)}` };

  const require = requireSessionFromSql(f.sql);
  assert.equal(await require(cookie), TENANT);

  const out = await handleLogout(cookie, deps);
  assert.equal(out.status, 200);
  assert.equal(await require(cookie), undefined, 'the session survived logout');
});

test('session: createSession sweeps rows that can no longer authenticate anything', async () => {
  const f = fakeSessionSql();
  const authToken = new Uint8Array(32).fill(5);
  f.loginCreds.set(TENANT, { tokenHashB64: b64(sha256(authToken)), kdf: validKdf() });

  // A long-dead session sits in the table.
  f.sessions.set(b64(hashSessionToken('D'.repeat(43))), {
    tenant: TENANT,
    expiresAt: NOW - HOUR_MS,
    lastSeenAt: NOW - HOUR_MS,
  });

  await handleLogin(loginBody(TENANT, b64(authToken)), authDepsFromSql(f.sql), '1.1.1.1');
  const rows = [...f.sessions.values()];
  assert.equal(rows.length, 1, 'the expired row must be swept by the login that follows it');
  assert.ok(rows[0]!.expiresAt > NOW);
});

/* ------------------------------------------------------------------ *
 * PUT /api/wrapped-keys — the device door
 * ------------------------------------------------------------------ */

async function putFixture() {
  const device = await generateDeviceKeypair(DEVICE);
  let clock = NOW;
  const nonces = new Set<string>();
  let uploadCount = 0;
  const stored: Array<{
    tenantId: string;
    keys: WrappedKey[];
    authTokenHash: Uint8Array | undefined;
  }> = [];
  const calls: string[] = [];

  const deps: PutWrappedKeyDeps = {
    lookupDevice: async (id) => {
      calls.push('lookupDevice');
      return id === DEVICE ? { publicKey: device.publicKey, revoked: false } : undefined;
    },
    rememberNonce: async (d, n) => {
      const k = `${d}|${n}`;
      if (nonces.has(k)) return false;
      nonces.add(k);
      return true;
    },
    now: () => clock,
    tenantIdForDevice: async (id) => (id === DEVICE ? TENANT : undefined),
    reserveUpload: async () => ++uploadCount,
    tenantBytesStored: async () => 0,
    storeWrappedKeys: async (tenantId, keys, authTokenHash) => {
      calls.push('store');
      stored.push({ tenantId, keys, authTokenHash });
    },
  };

  const put = async (body: unknown, sign: { path?: string; tamper?: boolean } = {}) => {
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const headers = await signRequest(
      {
        deviceId: DEVICE,
        method: ROUTES.putWrappedKey.method,
        path: sign.path ?? ROUTES.putWrappedKey.path,
        body: raw,
        timestamp: clock,
      },
      device.secretKey,
    );
    const sent = sign.tamper ? new TextEncoder().encode(JSON.stringify(body) + ' ') : raw;
    return { res: await handlePutWrappedKey(headers, sent, deps), headers, raw };
  };

  return {
    deps,
    put,
    stored,
    calls,
    device,
    setUploadCount: (n: number) => {
      uploadCount = n;
    },
  };
}

const validPutBody = () => ({
  keys: [syntheticKey('pass', validKdf()), syntheticKey('recovery')],
  authTokenHash: b64(sha256(new Uint8Array(32).fill(3))),
});

test('putWrappedKey: a signed PUT stores the blobs under the SIGNER\'S tenant', async () => {
  const f = await putFixture();
  const { res } = await f.put(validPutBody());
  assert.equal(res.status, 200);
  assert.equal(f.stored.length, 1);
  assert.equal(f.stored[0]!.tenantId, TENANT);
  assert.deepEqual(f.stored[0]!.keys.map((k) => k.kind).sort(), ['pass', 'recovery']);
});

test('putWrappedKey: a tenant smuggled into the body is ignored — auth decides, not JSON', async () => {
  const f = await putFixture();
  const { res } = await f.put({ ...validPutBody(), tenantId: 'tnt_evil', tenant: 'tnt_evil' });
  assert.equal(res.status, 200);
  assert.equal(f.stored[0]!.tenantId, TENANT);
  assert.ok(!JSON.stringify(f.stored).includes('tnt_evil'));
});

test('putWrappedKey: a tampered body fails the signature and stores NOTHING', async () => {
  const f = await putFixture();
  const { res } = await f.put(validPutBody(), { tamper: true });
  assert.equal(res.status, 401);
  assert.deepEqual(res.body, { ok: false, error: 'unauthorized' });
  assert.equal(f.stored.length, 0);
  assert.ok(!f.calls.includes('store'), 'authenticate BEFORE parse and store');
});

test('putWrappedKey: a signature minted for another path does not open this door', async () => {
  // The path is inside the Ed25519 signature; a capture from /api/sync must not replay here.
  const f = await putFixture();
  const { res } = await f.put(validPutBody(), { path: ROUTES.sync.path });
  assert.equal(res.status, 401);
  assert.equal(f.stored.length, 0);
});

test('putWrappedKey: a byte-identical replay is refused by the nonce defence', async () => {
  const f = await putFixture();
  const body = validPutBody();
  const { res, headers, raw } = await f.put(body);
  assert.equal(res.status, 200);

  const replay = await handlePutWrappedKey(headers, raw, f.deps);
  assert.equal(replay.status, 409);
  assert.equal(f.stored.length, 1, 'the replay stored a second time');
});

test('putWrappedKey: a revoked device is 403', async () => {
  const f = await putFixture();
  const revokedDeps: PutWrappedKeyDeps = {
    ...f.deps,
    lookupDevice: async () => ({ publicKey: f.device.publicKey, revoked: true }),
  };
  const raw = new TextEncoder().encode(JSON.stringify(validPutBody()));
  const headers = await signRequest(
    { deviceId: DEVICE, method: 'PUT', path: ROUTES.putWrappedKey.path, body: raw, timestamp: NOW },
    f.device.secretKey,
  );
  const res = await handlePutWrappedKey(headers, raw, revokedDeps);
  assert.equal(res.status, 403);
});

test('putWrappedKey: the admission gate meters this door too', async () => {
  const f = await putFixture();
  f.setUploadCount(MAX_UPLOADS_PER_HOUR_PER_DEVICE);
  const { res } = await f.put(validPutBody());
  assert.equal(res.status, 429);
  assert.equal(f.stored.length, 0);
});

test('putWrappedKey: an oversized body is refused before any authentication work', async () => {
  const f = await putFixture();
  const res = await handlePutWrappedKey({}, new Uint8Array(1_048_577), f.deps);
  assert.equal(res.status, 413);
  assert.equal(f.calls.length, 0, 'the size check must precede the device lookup');
});

test('putWrappedKey: a pass blob and an authTokenHash travel together or not at all', async () => {
  const f = await putFixture();
  const { authTokenHash } = validPutBody();

  const passAlone = await f.put({ keys: [syntheticKey('pass', validKdf())] });
  assert.equal(passAlone.res.status, 400);

  const hashAlone = await f.put({ keys: [syntheticKey('recovery')], authTokenHash });
  assert.equal(hashAlone.res.status, 400);

  assert.equal(f.stored.length, 0);
});

test('putWrappedKey: shape violations are each 400 and store nothing', async () => {
  const f = await putFixture();
  const hash = b64(sha256(new Uint8Array(32)));
  const kdf = validKdf();

  const bodies: unknown[] = [
    null,
    {},
    { keys: [] },
    { keys: [{ ...syntheticKey('pass', kdf), v: 1 }], authTokenHash: hash },
    { keys: [syntheticKey('device'), syntheticKey('device')] }, // duplicate kind
    { keys: [{ ...syntheticKey('pass', kdf), kind: 'root' }], authTokenHash: hash },
    { keys: [syntheticKey('pass')], authTokenHash: hash }, // pass without kdf
    { keys: [syntheticKey('recovery', kdf)] }, // kdf where none belongs
    { keys: [{ ...syntheticKey('pass', kdf), nonce: b64(new Uint8Array(12)) }], authTokenHash: hash },
    { keys: [{ ...syntheticKey('pass', kdf), ciphertext: 'not base64!!' }], authTokenHash: hash },
    { keys: [syntheticKey('pass', { ...kdf, m: 1024 })], authTokenHash: hash }, // below floor
    { keys: [syntheticKey('pass', { ...kdf, m: 2 ** 33 })], authTokenHash: hash }, // above ceiling
    { keys: [syntheticKey('pass', { ...kdf, t: 99 })], authTokenHash: hash },
    { keys: [syntheticKey('pass', { ...kdf, p: 4 as 1 })], authTokenHash: hash },
    { keys: [syntheticKey('pass', { ...kdf, salt: b64(new Uint8Array(8)) })], authTokenHash: hash },
    { keys: [syntheticKey('pass', kdf)], authTokenHash: 'AAAA' }, // hash too short
  ];
  for (const body of bodies) {
    const { res } = await f.put(body);
    assert.equal(res.status, 400, JSON.stringify(body)?.slice(0, 80));
  }
  assert.equal(f.stored.length, 0);
});

test('storeWrappedKeys (SQL): blobs first, credential LAST, kdf taken from the pass blob itself', async () => {
  const f = fakeSessionSql();
  const deps = wrappedKeyDepsFromSql(f.sql);
  const passKdf = { ...validKdf(), salt: b64(new Uint8Array(16).fill(42)) };
  const keys = [syntheticKey('pass', passKdf), syntheticKey('recovery')];
  const hash = sha256(new Uint8Array(32).fill(3));

  await deps.storeWrappedKeys(TENANT, keys, hash);

  // The credential's kdf IS the pass blob's kdf — the no-drift-by-construction property.
  const cred = f.loginCreds.get(TENANT)!;
  assert.deepEqual(cred.kdf, passKdf);
  assert.equal(cred.tokenHashB64, b64(hash));
  assert.deepEqual(f.wrappedKeys.get(`${TENANT}|pass`)!.blob.kdf, passKdf);

  // Ordering: every wrapped_key write precedes the credential write, so a partial failure
  // leaves the OLD credential (still logs in) rather than a credential with no matching blob.
  const kinds = f.queries.map((q) =>
    /INSERT INTO wrapped_key/.test(q.text) ? 'blob' : /INSERT INTO login_credential/.test(q.text) ? 'cred' : '',
  );
  assert.deepEqual(kinds.filter(Boolean), ['blob', 'blob', 'cred']);

  // No credential write at all when no auth hash was sent (a non-pass-only update).
  const f2 = fakeSessionSql();
  await wrappedKeyDepsFromSql(f2.sql).storeWrappedKeys(TENANT, [syntheticKey('recovery')], undefined);
  assert.equal(f2.loginCreds.size, 0);
});

/* ------------------------------------------------------------------ *
 * End to end: the whole loop, with the real crypto
 * ------------------------------------------------------------------ */

test('E2E: onboard -> prelogin -> derive -> login -> fetch -> unwrap, one coherent loop', async () => {
  const passphrase = 'correct horse battery staple';
  const identity = await generateIdentity();

  // THE BRIDGE, at onboarding: wrap the identity under the passphrase, derive the auth token
  // from the SAME root (same salt, same params — one Argon2id serves both), hash it, PUT both.
  const blob = await wrapUnderPassphrase(identity.secretKey, passphrase);
  const root = await deriveRoot(passphrase, blob.kdf!);
  const authToken = await hkdf(root, AUTH_KDF_INFO);
  const authTokenHash = sha256(authToken);

  const f = await putFixture();
  const { res: putRes } = await f.put({ keys: [blob], authTokenHash: b64(authTokenHash) });
  assert.equal(putRes.status, 200);

  // What the PUT persisted becomes the auth deps' world.
  const persisted = f.stored[0]!;
  const { deps: authDeps } = fakeAuthDeps({
    getLoginCredential: async (t) =>
      t === persisted.tenantId
        ? { tokenHash: persisted.authTokenHash!, kdf: persisted.keys[0]!.kdf! }
        : undefined,
  });

  // THE BROWSER: prelogin hands back the very params sealed into the blob...
  const pre = await handlePrelogin(TENANT, authDeps, '1.1.1.1');
  const preKdf = dataOf(pre).kdf;
  assert.deepEqual(preKdf, blob.kdf);

  // ...so ONE derivation yields both the login token and (via the sibling label) the KEK.
  const browserRoot = await deriveRoot(passphrase, preKdf);
  const browserToken = await hkdf(browserRoot, AUTH_KDF_INFO);
  assert.deepEqual(browserToken, authToken);

  const login = await handleLogin(loginBody(TENANT, b64(browserToken)), authDeps, '1.1.1.1');
  assert.equal(login.status, 200, JSON.stringify(login.body));

  // The stored blob opens with the passphrase and yields the identity key — and the auth token
  // the server DID see opens nothing: it is not the KEK and cannot be turned into it.
  const opened = await unwrapWithPassphrase(persisted.keys[0]!, passphrase);
  assert.deepEqual(opened, identity.secretKey);
  const kek = await hkdf(browserRoot, KDF_INFO.kek);
  assert.notDeepEqual(authToken, kek, 'the auth token must not BE the KEK');

  // A wrong passphrase fails at the AEAD, as it must.
  await assert.rejects(() => unwrapWithPassphrase(persisted.keys[0]!, 'tally123'));
});

test('the auth HKDF label is distinct from every WRAPPING label (domain separation)', () => {
  // This test used to read `!Object.values(KDF_INFO).includes(AUTH_KDF_INFO)`, which was right
  // only while the auth label lived here and not in packages/crypto. Now that `KDF_INFO.auth`
  // exists — and AUTH_KDF_INFO is re-exported FROM it, so the two can never drift — that check
  // compares the label to itself and fails. The property it was reaching for was never "auth is
  // absent from KDF_INFO"; it was "auth is not one of the labels that unwraps a key".
  //
  // Named explicitly rather than derived, because the whole point is to notice if someone later
  // makes `auth` collide with one of these. A test that computes the answer from the same object
  // it is checking cannot notice anything.
  // `readonly string[]`, not the inferred literal union: `includes` on a narrowed array rejects
  // a plain `string` argument, and widening the HAYSTACK is right where widening the needle
  // would be a cast that defeats the check.
  const wrapping: readonly string[] = [KDF_INFO.kek, KDF_INFO.recovery, KDF_INFO.device];
  assert.ok(
    !wrapping.includes(AUTH_KDF_INFO),
    'the auth token would BE a wrapping key: the server would hold a hash of the key that ' +
      'opens the identity, and the entire E2E claim would be void',
  );
  assert.equal(AUTH_KDF_INFO, KDF_INFO.auth, 'the server must not restate the label');
});

test('every KDF label is distinct — the invariant, not just the auth case', () => {
  // The general form. HKDF's sibling independence is only worth anything if the siblings are
  // actually distinct: two labels that are accidentally equal produce the SAME key, silently,
  // and every argument about domain separation in this file evaporates. Cheap to check, and it
  // covers the labels nobody is thinking about today.
  const labels = Object.values(KDF_INFO);
  assert.equal(new Set(labels).size, labels.length, `duplicate HKDF label in ${labels.join(', ')}`);
});

/* ------------------------------------------------------------------ *
 * Schema
 * ------------------------------------------------------------------ */

test('schema: the auth tables exist, split cleanly, and the secret is minted from the CSPRNG', () => {
  const schema = readFileSync(new URL('../src/schema.sql', import.meta.url), 'utf8');
  const statements = splitStatements(schema);

  for (const table of ['login_credential', 'session', 'auth_window', 'deployment_secret']) {
    assert.ok(
      statements.some((s) => s.startsWith(`CREATE TABLE IF NOT EXISTS ${table}`)),
      `missing table ${table}`,
    );
  }
  assert.ok(
    statements.some((s) => s.startsWith('CREATE INDEX IF NOT EXISTS ix_session_expiry')),
    'the session sweep needs its expiry index',
  );

  const mint = statements.find((s) => s.startsWith('INSERT INTO deployment_secret'));
  assert.ok(mint, 'the deployment secret is never minted');
  // gen_random_uuid() draws from pg_strong_random; random() does not and must not appear.
  assert.match(mint!, /gen_random_uuid/);
  assert.ok(!/[^_]random\(\)/.test(mint!), 'the secret must come from the CSPRNG, not random()');
  assert.match(mint!, /ON CONFLICT \(id\) DO NOTHING/, 'the mint must be idempotent across cold starts');
});
