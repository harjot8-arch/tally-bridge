import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ALL_ROUTES, ROUTES, generateDeviceKeypair, signRequest, verifyRequest } from '../src/index.ts';

/**
 * Tests for the route table.
 *
 * The bar here is deliberately "would this fail if the table were wrong", not "does the table
 * exist". A test that reads `ROUTES.sync.path` and asserts it equals `'/api/sync'` is a
 * tautology dressed as a test: it restates the definition, and it stays green through every
 * mutation that matters. So none of these do that.
 *
 * What can actually go wrong with a route table, in the order it will:
 *   1. Two routes collide, so the router's behaviour depends on iteration order.
 *   2. A path is signed by one side and verified by another, and they differ.
 *   3. A route is added to the table and never mounted (that one belongs to the router's tests,
 *      which own the handler map — see apps/server).
 */

test('no two routes share a method+path — a collision makes the router order-dependent', () => {
  const seen = new Map<string, string>();
  for (const r of ALL_ROUTES) {
    const key = `${r.method} ${r.path}`;
    const prior = seen.get(key);
    assert.equal(
      prior,
      undefined,
      `routes '${prior}' and '${r.name}' both claim ${key}; whichever the router happens to ` +
        `match first would win, which is not a decision anyone made`,
    );
    seen.set(key, r.name);
  }
});

/**
 * `/api/wrapped-keys` is intentionally one path with two methods (GET reads through the session
 * door, PUT writes through the device door). That is legal and deliberate — this test pins that
 * the SPLIT IS BY METHOD, so the router can never dispatch a PUT to the session-authenticated
 * reader.
 */
test('a path shared by two routes must differ by method, and may not share an auth door', () => {
  const byPath = new Map<string, typeof ALL_ROUTES[number][]>();
  for (const r of ALL_ROUTES) {
    const list = byPath.get(r.path) ?? [];
    list.push(r);
    byPath.set(r.path, list);
  }
  for (const [path, routes] of byPath) {
    if (routes.length === 1) continue;
    const methods = new Set(routes.map((r) => r.method));
    assert.equal(methods.size, routes.length, `${path}: methods must be distinct`);
    // Not a style rule. `/api/wrapped-keys` GET is 'session' and PUT is 'device' — if a future
    // edit made both 'session', the Bridge (which holds no session) could no longer write, and
    // if both were 'device', a stolen device key could READ the wrapped identity key. The two
    // doors exist precisely so that neither is possible.
    const doors = new Set(routes.map((r) => r.auth));
    assert.ok(doors.size > 1, `${path}: two routes on one path collapsed to a single auth door`);
  }
});

test('every route is under /api/ — the static dashboard owns every other path', () => {
  for (const r of ALL_ROUTES) {
    assert.ok(r.path.startsWith('/api/'), `${r.name} is '${r.path}'`);
    assert.ok(!r.path.endsWith('/'), `${r.name} has a trailing slash, which will not match`);
  }
});

/**
 * THE ONE THAT MATTERS.
 *
 * This is the whole reason the table exists, and it is the only test here that would have caught
 * the bug that motivated it. It does not compare strings — it runs the REAL signer and the REAL
 * verifier over the table's own value, and then proves that a DIFFERENT path fails.
 *
 * If someone re-introduces a literal on either side and the two drift apart, the second half of
 * this test is what that drift looks like in production: a correct signature over a correct
 * body, refused.
 */
test('a signature made over the table\'s path verifies; one made over a neighbour does not', async () => {
  const kp = await generateDeviceKeypair('dev_1');
  const body = new TextEncoder().encode('{"ciphertext":"..."}');
  const NOW = 1_700_000_000_000;

  const deps = {
    lookupDevice: async (id: string) =>
      id === 'dev_1' ? { publicKey: kp.publicKey, revoked: false } : undefined,
    rememberNonce: async () => true,
    admit: async () => ({ ok: true }) as const,
    now: () => NOW,
  };

  const headers = await signRequest(
    {
      deviceId: 'dev_1',
      method: ROUTES.sync.method,
      path: ROUTES.sync.path,
      body,
      timestamp: NOW,
    },
    kp.secretKey,
  );

  const good = await verifyRequest(
    headers,
    { method: ROUTES.sync.method, path: ROUTES.sync.path, body },
    deps,
  );
  assert.equal(good.ok, true, 'the table\'s own path must verify against itself');

  // The drift, simulated: the server mounts this handler one character away from where the
  // Bridge signed. Nothing about the request is forged; the signature is genuine and the body
  // is untouched. It is refused anyway, and the owner sees "invalid signature" — the one thing
  // that is not actually wrong.
  const drifted = await verifyRequest(
    headers,
    { method: ROUTES.sync.method, path: `${ROUTES.sync.path}/`, body },
    { ...deps, rememberNonce: async () => true },
  );
  assert.equal(drifted.ok, false, 'a path that drifted by one character must NOT verify');
});
