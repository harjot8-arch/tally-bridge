import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { ALL_ROUTES, MAX_PAYLOAD_BYTES } from '@tally-bridge/protocol';
import {
  createRouter,
  type MountedHandler,
  type RouterHandlers,
  type RouterRequest,
  type SessionCheck,
} from '../src/router.ts';
import {
  buildHandlers,
  createRequestListener,
  handleHttpRequest,
  type EntryDeps,
} from '../src/entry.ts';
import type { Db, Sql } from '../src/db.ts';

/**
 * The router and the HTTP entry.
 *
 * The first test is the one this file exists for: EVERY route in the shared table must be
 * mounted and dispatchable. A route someone adds to routes.ts and forgets to mount must fail
 * here, on this machine, not as a customer's 404 after they have paid Vercel.
 *
 * Mutations run against these tests (each was applied, observed red, and reverted):
 *   - remove a route from the handler map        -> construction throws / mount test red
 *   - flip a handler's declared auth door        -> construction throws
 *   - delete the router's session gate           -> the misbehaving-handler test leaks a 200
 *   - normalise trailing slashes in dispatch     -> the byte-identical-path test red
 *   - migrate on unmatched paths                 -> the scanner test red
 */

/* ------------------------------------------------------------------ helpers */

const fakeSql: Sql = async () => [];

function fakeDb(): Db {
  return { sql: fakeSql, transaction: async () => {} };
}

interface Spies {
  migrations: number;
  connects: number;
  sessionCalls: number;
}

function deps(overrides: Partial<EntryDeps> = {}): { deps: EntryDeps; spies: Spies } {
  const spies: Spies = { migrations: 0, connects: 0, sessionCalls: 0 };
  const base: EntryDeps = {
    connectDb: () => {
      spies.connects++;
      return fakeDb();
    },
    ensureMigrated: async () => {
      spies.migrations++;
    },
    loadSchema: async () => 'CREATE TABLE IF NOT EXISTS x (id TEXT)',
    // EntryDeps.requireSession is a factory over the request's Sql (see entry.ts); the fake
    // ignores the handle.
    requireSession: () => async () => {
      spies.sessionCalls++;
      return undefined;
    },
    env: {},
  };
  return { deps: { ...base, ...overrides }, spies };
}

const rr = (method: string, path: string, body: Uint8Array = new Uint8Array()): RouterRequest => ({
  method,
  path,
  headers: {},
  body,
});

const sessionOf =
  (tenant: string | undefined, spies?: Spies): SessionCheck =>
  async () => {
    if (spies) spies.sessionCalls++;
    return tenant;
  };

/* ------------------------------------------------------------------ the mount test */

test('every route in ALL_ROUTES is mounted and dispatchable', async () => {
  const { deps: d } = deps();
  assert.ok(ALL_ROUTES.length >= 11, 'the route table shrank; is the right protocol built?');

  for (const route of ALL_ROUTES) {
    const res = await handleHttpRequest(d, rr(route.method, route.path));
    // 404/405 mean "not mounted"; 500 is how a construction failure (unmounted or mis-tagged
    // route) surfaces through the entry. Any of them here is the bug this file exists to stop.
    assert.notEqual(res.status, 404, `route '${route.name}' (${route.method} ${route.path}) is not mounted`);
    assert.notEqual(res.status, 405, `route '${route.name}' is mounted under the wrong method`);
    assert.notEqual(res.status, 500, `route '${route.name}' blew up on dispatch`);
  }
});

test('an unauthenticated, empty-bodied request cannot reach data on any route', async () => {
  const { deps: d } = deps();
  for (const route of ALL_ROUTES) {
    const res = await handleHttpRequest(d, rr(route.method, route.path));
    const body = res.body as { ok: boolean; data?: unknown };
    if (route.name === 'health') {
      assert.equal(res.status, 200);
      continue;
    }
    assert.equal(body.ok, false, `${route.name}: anonymous request was accepted`);
    assert.equal(body.data, undefined, `${route.name}: anonymous request received data`);
  }
});

/* ------------------------------------------------------------------ construction refusals */

test('createRouter refuses a handler map missing a route', () => {
  const handlers = buildHandlers({ sql: fakeSql, env: {}, requireSession: sessionOf(undefined) });
  const { sync: _dropped, ...rest } = handlers;
  assert.throws(
    () => createRouter(rest as unknown as RouterHandlers, sessionOf(undefined)),
    /sync/,
  );
});

test('createRouter refuses a handler whose declared door disagrees with the table', () => {
  const handlers = buildHandlers({ sql: fakeSql, env: {}, requireSession: sessionOf(undefined) });
  const mislabelled: RouterHandlers = {
    ...handlers,
    snapshots: { auth: 'none', handle: handlers.snapshots.handle },
  };
  assert.throws(() => createRouter(mislabelled, sessionOf(undefined)), /snapshots/);
});

/* ------------------------------------------------------------------ the session gate */

/** A handler that forgets its own auth check and hands out data unconditionally. */
const leakyHandler: MountedHandler = {
  auth: 'session',
  handle: async () => ({ status: 200, body: { ok: true, data: 'LEAK' } }),
};

test('the router 401s a session route even when the handler itself forgets to check', async () => {
  const handlers = buildHandlers({ sql: fakeSql, env: {}, requireSession: sessionOf(undefined) });
  const dispatch = createRouter({ ...handlers, snapshots: leakyHandler }, sessionOf(undefined));

  const res = await dispatch(rr('GET', '/api/snapshots'));
  assert.equal(res.status, 401);
  assert.ok(!JSON.stringify(res.body).includes('LEAK'), 'the router let an unauthenticated leak through');
});

test('the session gate admits a valid session (it is a gate, not a wall)', async () => {
  const handlers = buildHandlers({ sql: fakeSql, env: {}, requireSession: sessionOf('tn_1') });
  const dispatch = createRouter({ ...handlers, snapshots: leakyHandler }, sessionOf('tn_1'));
  const res = await dispatch(rr('GET', '/api/snapshots'));
  assert.equal(res.status, 200);
});

test('one session lookup serves both the router gate and the handler', async () => {
  const spies: Spies = { migrations: 0, connects: 0, sessionCalls: 0 };
  const { deps: d } = deps({ requireSession: () => sessionOf('tn_1', spies) });
  const res = await handleHttpRequest(d, rr('GET', '/api/snapshots'));
  assert.equal(res.status, 200); // fakeSql returns [] rows -> an empty, authorised list
  assert.equal(spies.sessionCalls, 1, 'session lookup ran more than once for one request');
});

/* ------------------------------------------------------------------ dispatch precision */

test('unknown paths 404 and touch neither the database nor the migrator', async () => {
  const { deps: d, spies } = deps();
  const res = await handleHttpRequest(d, rr('GET', '/wp-admin/setup.php'));
  assert.equal(res.status, 404);
  assert.equal(spies.connects, 0, 'a scanner 404 opened a database connection');
  assert.equal(spies.migrations, 0);
});

test('a known path under the wrong method is 405', async () => {
  const { deps: d } = deps();
  const res = await handleHttpRequest(d, rr('DELETE', '/api/sync'));
  assert.equal(res.status, 405);
});

test('the path match is byte-identical: a trailing slash is a different (unsigned) path', async () => {
  // The path is inside the Ed25519 signature. A router that normalised '/api/sync/' into a
  // dispatch to the sync handler would verify against a string the device never signed — the
  // silent-401 failure routes.ts exists to prevent. 404 is the honest answer.
  const { deps: d } = deps();
  const res = await handleHttpRequest(d, rr('POST', '/api/sync/'));
  assert.equal(res.status, 404);
});

/* ------------------------------------------------------------------ migration ordering */

test('health touches neither the database nor the migrator', async () => {
  const { deps: d, spies } = deps({
    connectDb: () => {
      throw new Error('health must stay answerable while Neon is down');
    },
  });
  const res = await handleHttpRequest(d, rr('GET', '/api/health'));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true });
  assert.equal(spies.migrations, 0);
});

test('a data route migrates before dispatch', async () => {
  const { deps: d, spies } = deps();
  await handleHttpRequest(d, rr('GET', '/api/snapshots'));
  assert.equal(spies.migrations, 1);
  assert.equal(spies.connects, 1);
});

/* ------------------------------------------------------------------ error hygiene */

test('an internal failure is one plain sentence — no message, no stack, no class name', async () => {
  const { deps: d } = deps({
    connectDb: () => {
      throw new Error("connect ECONNREFUSED 127.0.0.1:5432 at TCPConnectWrap.afterConnect");
    },
  });
  // No console shim needed: the entry does not log — read.test.ts's no-logging scan is the
  // policy, and entry.ts now honours it (the 500 stays a silent one-sentence answer).
  const res = await handleHttpRequest(d, rr('GET', '/api/snapshots'));
  assert.equal(res.status, 500);
  const text = JSON.stringify(res.body);
  assert.ok(!text.includes('ECONNREFUSED'), 'driver internals reached the response body');
  assert.ok(!text.includes('at TCP'), 'a stack frame reached the response body');
  assert.match((res.body as { error: string }).error, /^[^\n]+$/, 'error is not one plain line');
});

/* ------------------------------------------------------------------ the Node listener */

function fakeHttp(method: string, url: string, chunks: Buffer[] = []) {
  const req = Readable.from(chunks) as unknown as IncomingMessage;
  (req as { method?: string }).method = method;
  (req as { url?: string }).url = url;
  (req as { headers?: object }).headers = {};
  const captured = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    body: '',
  };
  const res = {
    set statusCode(v: number) {
      captured.statusCode = v;
    },
    get statusCode() {
      return captured.statusCode;
    },
    setHeader(k: string, v: string) {
      captured.headers[k] = v;
    },
    end(b: string) {
      captured.body = b;
    },
  } as unknown as ServerResponse;
  return { req, res, captured };
}

test('the listener serves health over the wire shape Vercel invokes', async () => {
  const { deps: d } = deps();
  const listener = createRequestListener(d);
  const { req, res, captured } = fakeHttp('GET', '/api/health');
  await listener(req, res);
  assert.equal(captured.statusCode, 200);
  assert.deepEqual(JSON.parse(captured.body), { ok: true });
  assert.equal(captured.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(captured.headers['cache-control'], 'no-store');
});

test('the listener refuses an oversized body with 413 while a body of exactly the cap passes', async () => {
  const { deps: d } = deps();
  const listener = createRequestListener(d);

  // Against REGISTER, not sync, deliberately: handleIngest has its own 413, so an oversized
  // sync body cannot tell this transport-layer cap from the handler's. handleRegister has no
  // size check at all — a 413 here can only have come from the listener, and it is precisely
  // the route that FORGOT its own cap that this layer exists to protect. (Mutation: multiply
  // the cap by 1000 and this asserts 400 — the JSON parser saw the whole 1MB+ body.)
  const over = fakeHttp('POST', '/api/register', [Buffer.alloc(MAX_PAYLOAD_BYTES + 1)]);
  await listener(over.req, over.res);
  assert.equal(over.captured.statusCode, 413);

  // Exactly the cap must survive THIS layer (handleIngest rejects strictly-greater): here it
  // proceeds to auth and dies as an unsigned request, not as an oversized one.
  const exact = fakeHttp('POST', '/api/sync', [Buffer.alloc(MAX_PAYLOAD_BYTES)]);
  await listener(exact.req, exact.res);
  assert.equal(exact.captured.statusCode, 401);
});

test('the listener query string does not defeat path matching', async () => {
  const { deps: d } = deps();
  const listener = createRequestListener(d);
  const { req, res, captured } = fakeHttp('GET', '/api/health?probe=1');
  await listener(req, res);
  assert.equal(captured.statusCode, 200);
});
