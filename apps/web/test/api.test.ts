import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError } from '../src/data/api.ts';
import { prelogin, login, wrappedKeys, snapshots } from '../src/data/api.ts';
import type { FetchLike } from '../src/data/api.ts';

/**
 * The HTTP client treats every response as HOSTILE input. These tests feed it the malformed
 * and adversarial shapes a lying server can produce and assert each one becomes a named
 * ApiError (or is dropped and counted) instead of a TypeError deep in the crypto.
 */

const json =
  (status: number, body: unknown): FetchLike =>
  async () =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

// ---------------------------------------------------------------- transport failures

test('network failure becomes ApiError status 0, not a raw TypeError', async () => {
  const f: FetchLike = async () => {
    throw new TypeError('fetch failed');
  };
  await assert.rejects(prelogin(f, 't_1'), (e: unknown) => e instanceof ApiError && e.status === 0);
});

test('a non-JSON body is refused with the response status attached', async () => {
  const f: FetchLike = async () => new Response('<html>gateway error</html>', { status: 502 });
  await assert.rejects(prelogin(f, 't_1'), (e: unknown) => e instanceof ApiError && e.status === 502);
});

test('ok:false and non-2xx are both refusals; the error string is passed through when a string', async () => {
  await assert.rejects(
    prelogin(json(200, { ok: false, error: 'rate limited' }), 't_1'),
    (e: unknown) => e instanceof ApiError && e.message === 'rate limited',
  );
  await assert.rejects(
    prelogin(json(500, { ok: true, data: {} }), 't_1'),
    (e: unknown) => e instanceof ApiError && e.status === 500,
  );
  // A hostile error VALUE (object, number) must not reach the UI as "[object Object]".
  await assert.rejects(
    prelogin(json(400, { ok: false, error: { evil: true } }), 't_1'),
    (e: unknown) => e instanceof ApiError && e.message === 'request failed (400)',
  );
});

// ---------------------------------------------------------------- prelogin KDF validation

const goodKdf = { v: 1, kdf: 'argon2id', m: 67108864, t: 3, p: 1, salt: 'c2FsdHNhbHRzYWx0c2E=' };

test('prelogin passes through a well-formed KDF descriptor field by field', async () => {
  const kdf = await prelogin(json(200, { ok: true, data: { kdf: goodKdf } }), 't_1');
  assert.deepEqual(kdf, goodKdf);
});

test('prelogin refuses every malformed KDF shape a lying server can serve', async () => {
  const cases: Array<[string, unknown]> = [
    ['missing kdf', {}],
    ['kdf not an object', { kdf: 'argon2id' }],
    ['unknown scheme', { kdf: { ...goodKdf, kdf: 'pbkdf2' } }],
    ['wrong version', { kdf: { ...goodKdf, v: 2 } }],
    ['parallelism not 1', { kdf: { ...goodKdf, p: 4 } }],
    // m/t as STRINGS is the shape that would coerce somewhere downstream if the typeof check
    // were replaced with a `!` assertion — the exact hole the typecheck error pointed at.
    ['m as string', { kdf: { ...goodKdf, m: '67108864' } }],
    ['t as string', { kdf: { ...goodKdf, t: '3' } }],
    ['m missing', { kdf: { ...goodKdf, m: undefined } }],
    ['m fractional', { kdf: { ...goodKdf, m: 1.5 } }],
    ['t NaN', { kdf: { ...goodKdf, t: NaN } }],
    ['salt missing', { kdf: { ...goodKdf, salt: undefined } }],
    ['salt empty', { kdf: { ...goodKdf, salt: '' } }],
  ];
  for (const [name, data] of cases) {
    await assert.rejects(
      prelogin(json(200, { ok: true, data }), 't_1'),
      (e: unknown) => e instanceof ApiError && /unusable KDF params/.test(e.message),
      `case "${name}" must be refused`,
    );
  }
});

test('prelogin URL-encodes the tenant id', async () => {
  let seen = '';
  const f: FetchLike = async (path) => {
    seen = path;
    return new Response(JSON.stringify({ ok: true, data: { kdf: goodKdf } }), { status: 200 });
  };
  await prelogin(f, 'a b&c=d');
  assert.ok(seen.endsWith('?tenant=a%20b%26c%3Dd'), `got ${seen}`);
});

// ---------------------------------------------------------------- wrapped keys projection

test('wrappedKeys rebuilds rows field by field — a server-attached roster field is DROPPED', async () => {
  const hostile = {
    v: 2,
    kind: 'pass',
    nonce: 'bm9uY2U=',
    ciphertext: 'Y3Q=',
    kdf: goodKdf,
    // The attack the projection exists to stop: a roster the SERVER picked, riding on the
    // blob. There is deliberately no such field in the real WrappedKey type; if one arrives,
    // it must not survive into anything a caller could be tempted to pass to openSection.
    roster: [{ deviceId: 'dev_evil', publicKey: 'x'.repeat(43) + '=' }],
    trustedDevices: [{ deviceId: 'dev_evil' }],
  };
  const keys = await wrappedKeys(json(200, { ok: true, data: [hostile] }));
  assert.equal(keys.length, 1);
  assert.ok(!('roster' in keys[0]!), 'server-supplied roster field must be stripped');
  assert.ok(!('trustedDevices' in keys[0]!), 'server-supplied trustedDevices must be stripped');
  assert.deepEqual(Object.keys(keys[0]!).sort(), ['ciphertext', 'kdf', 'kind', 'nonce', 'v']);
});

test('wrappedKeys drops rows with unknown version, unknown kind, or missing ciphertext', async () => {
  const rows = [
    { v: 1, kind: 'pass', nonce: 'a', ciphertext: 'b' }, // old version
    { v: 2, kind: 'session', nonce: 'a', ciphertext: 'b' }, // unknown kind
    { v: 2, kind: 'pass', nonce: 'a' }, // no ciphertext
    null,
    'garbage',
    { v: 2, kind: 'recovery', nonce: 'a', ciphertext: 'b' }, // valid
  ];
  const keys = await wrappedKeys(json(200, { ok: true, data: rows }));
  assert.equal(keys.length, 1);
  assert.equal(keys[0]!.kind, 'recovery');
});

test('wrappedKeys refuses a non-list body', async () => {
  await assert.rejects(wrappedKeys(json(200, { ok: true, data: { not: 'a list' } })), ApiError);
});

// ---------------------------------------------------------------- snapshots validation

const goodRow = {
  companyGuid: 'guid-1',
  section: 'cash_bank',
  asOf: '2026-07-16',
  snapshotTs: 1000,
  seq: 1,
  envelope: { aad: {}, nonce: 'n', sealedCek: 's', ciphertext: 'c', contentHash: 'h' },
};

test('snapshots keeps well-formed rows and COUNTS malformed ones instead of hiding them', async () => {
  const rows = [
    goodRow,
    { ...goodRow, section: 'not_a_section' },
    { ...goodRow, asOf: '16-07-2026' },
    { ...goodRow, snapshotTs: '1000' },
    { ...goodRow, seq: 1.5 },
    { ...goodRow, envelope: null },
    { ...goodRow, companyGuid: '' },
    null,
    42,
  ];
  const out = await snapshots(json(200, { ok: true, data: rows }));
  assert.equal(out.rows.length, 1);
  assert.equal(out.malformed, 8);
});

test('login resolves on ok:true and throws ApiError with status on refusal', async () => {
  await login(json(200, { ok: true, data: {} }), 't_1', 'dG9rZW4=');
  await assert.rejects(
    login(json(401, { ok: false, error: 'bad credentials' }), 't_1', 'dG9rZW4='),
    (e: unknown) => e instanceof ApiError && e.status === 401,
  );
});
