import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import { MAX_PAYLOAD_BYTES, bootstrapSecretMatches } from '@tally-bridge/protocol';
import { handleLogin, handleLogout, handlePrelogin, handlePutWrappedKey } from './auth.ts';
import {
  authDepsFromSql,
  connect,
  ingestDepsFromSql,
  readDepsFromSql,
  registerDepsFromSql,
  requireSessionFromSql,
  wrappedKeyDepsFromSql,
  type Db,
  type Sql,
} from './db.ts';
import { handleIngest, handleRegister } from './ingest.ts';
import {
  handleGetWrappedKeys,
  handleListDevices,
  handleListSnapshots,
  handleRevokeDevice,
} from './read.ts';
import { createMigrator, loadSchemaFromDisk, type MigrateDeps } from './migrate.ts';
import {
  ALL_ROUTES,
  createRouter,
  type RouterHandlers,
  type RouterRequest,
  type RouterResponse,
  type SessionCheck,
} from './router.ts';

/**
 * The HTTP entrypoint — the file the Vercel function actually runs.
 *
 * This is the ONLY file that knows the transport. Everything interesting lives in the pure
 * handlers (ingest.ts, read.ts) and the router (router.ts); this file's whole job is:
 *
 *   read raw bytes -> migrate-once -> build per-request deps -> dispatch -> write JSON
 *
 * It is written against plain `(IncomingMessage, ServerResponse)` with NO Vercel helpers
 * (`shouldAddHelpers: false` in the bundle's .vc-config.json), for one non-negotiable reason:
 * the helpers parse a JSON body and hand you `req.body` — and the Ed25519 upload signature
 * covers the RAW BYTES. Re-serialising parsed JSON is not byte-identical (key order, number
 * formatting), so a helper-shaped entry would 401 every honest upload. The raw stream is the
 * contract.
 */

/** The one sentence a caller sees when this server breaks. The real error goes to the log. */
const GENERIC_ERROR = 'Something went wrong on the server. Please try again.';

const err = (status: number, error: string): RouterResponse => ({
  status,
  body: { ok: false, error },
});

/* ------------------------------------------------------------------ *
 * Handler map
 * ------------------------------------------------------------------ */

export interface HandlerContext {
  sql: Sql;
  env: Record<string, string | undefined>;
  requireSession: SessionCheck;
}

/**
 * Mount every route in the shared table.
 *
 * The `auth` tags below are WRITTEN AS LITERALS on purpose, not copied from `ROUTES[x].auth`.
 * Each tag is this file's independent claim about which door the handler implements; the router
 * compares claim against table at construction and throws on disagreement. Copying the table's
 * value here would make the check compare the table with itself — always green, checking
 * nothing.
 */
export function buildHandlers(ctx: HandlerContext): RouterHandlers {
  const readDeps = readDepsFromSql(ctx.sql, ctx.requireSession);

  return {
    sync: {
      auth: 'device',
      // The device door is INSIDE handleIngest (verifyRequest binds method, path, body, nonce);
      // the router cannot verify it generically. See router.ts.
      handle: (req) => handleIngest(req.headers, req.body, ingestDepsFromSql(ctx.sql), req.clientIp),
    },

    register: {
      auth: 'none',
      handle: async (req) => {
        const parsed = parseJsonObject(req.body);
        if (!parsed.ok) return err(400, parsed.error);
        return handleRegister(
          parsed.value,
          registerDepsFromSql(ctx.sql, ctx.env['BOOTSTRAP_SECRET']),
          bootstrapSecretMatches,
        );
      },
    },

    putWrappedKey: {
      auth: 'device',
      // Same shape as sync: the Ed25519 door is INSIDE the handler (verifyRequest needs the
      // raw body and the exact signed path), so raw bytes go through untouched.
      handle: (req) => handlePutWrappedKey(req.headers, req.body, wrappedKeyDepsFromSql(ctx.sql)),
    },

    prelogin: {
      auth: 'none',
      handle: (req) => handlePrelogin(req.query?.['tenant'], authDepsFromSql(ctx.sql), req.clientIp),
    },

    login: {
      auth: 'none',
      // Raw bytes in; the handler owns its (smaller) size cap, parse, meter and compare order.
      handle: (req) => handleLogin(req.body, authDepsFromSql(ctx.sql), req.clientIp),
    },

    logout: {
      auth: 'session',
      handle: (req) => handleLogout(req.headers, authDepsFromSql(ctx.sql)),
    },

    snapshots: {
      auth: 'session',
      handle: (req) => handleListSnapshots(req.headers, readDeps),
    },

    wrappedKeys: {
      auth: 'session',
      handle: (req) => handleGetWrappedKeys(req.headers, readDeps),
    },

    devices: {
      auth: 'session',
      handle: (req) => handleListDevices(req.headers, readDeps),
    },

    revokeDevice: {
      auth: 'session',
      handle: async (req) => {
        const parsed = parseJsonObject(req.body);
        if (!parsed.ok) return err(400, parsed.error);
        const deviceId = parsed.value['deviceId'];
        // Non-string shapes collapse to '' so handleRevokeDevice's own 400 answers; String()
        // would coerce an object into a "valid" id.
        return handleRevokeDevice(req.headers, typeof deviceId === 'string' ? deviceId : '', readDeps);
      },
    },

    health: {
      auth: 'none',
      // No tenant data, no table, no migration — see handleHttpRequest, which skips the
      // database entirely for this route so liveness stays answerable while Neon is down.
      handle: async () => ({ status: 200, body: { ok: true } }),
    },
  };
}

function parseJsonObject(
  body: Uint8Array,
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return { ok: false, error: 'body is not valid JSON' };
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    return { ok: false, error: 'body is not a JSON object' };
  }
  return { ok: true, value: v as Record<string, unknown> };
}

/* ------------------------------------------------------------------ *
 * Request handling
 * ------------------------------------------------------------------ */

export interface EntryDeps {
  /** Per-request, per db.ts Rule 1. Throws a loud error when DATABASE_URL is unset. */
  connectDb: () => Db;
  /** A `createMigrator()` memo. Held at module scope in this file; injected for tests. */
  ensureMigrated: (deps: MigrateDeps) => Promise<void>;
  loadSchema: () => Promise<string>;
  /**
   * A FACTORY over the request's Sql handle, not a bare SessionCheck: the real implementation
   * (`requireSessionFromSql`) needs the per-request connection, which does not exist at the
   * module scope where EntryDeps is assembled. Handed `sqlUnreachable` when no route matched,
   * where its fail-closed contract turns the unreachable query into `undefined`, never a throw.
   */
  requireSession: (sql: Sql) => SessionCheck;
  env: Record<string, string | undefined>;
}

/**
 * One session lookup per request, shared by the router's gate and the read handlers' own
 * checks. The headers are fixed for the life of a request, so caching the first answer is
 * sound — and it is what lets the router double-check auth without doubling the query.
 */
function memoiseSession(check: SessionCheck): SessionCheck {
  let cached: Promise<string | undefined> | undefined;
  return (headers) => (cached ??= check(headers));
}

/** Transport-independent core, so tests exercise it without faking Node streams. */
export async function handleHttpRequest(deps: EntryDeps, req: RouterRequest): Promise<RouterResponse> {
  try {
    const matched = ALL_ROUTES.find(
      (r) => r.path === req.path && r.method === req.method.toUpperCase(),
    );

    // Migration runs lazily on the first request that needs a table (see migrate.ts for why
    // nothing else can run it). Two deliberate exclusions:
    //   - health: liveness must not depend on the database.
    //   - unmatched requests: an unauthenticated scanner's 404s must not be able to open
    //     database connections on the client's bill.
    const db = matched && matched.name !== 'health' ? deps.connectDb() : undefined;
    if (db) {
      await deps.ensureMigrated({ transaction: db.transaction, loadSchema: deps.loadSchema });
    }

    const sql = db?.sql ?? sqlUnreachable;
    const session = memoiseSession(deps.requireSession(sql));
    const dispatch = createRouter(
      buildHandlers({ sql, env: deps.env, requireSession: session }),
      session,
    );
    return await dispatch(req);
  } catch (e) {
    // One sentence out, and NOTHING to the log. This catch used to `console.error(e)` "so the
    // operator can read the truth", and the no-logging test in read.test.ts rightly refuses it:
    // a Vercel log is retained, searchable, read by whoever holds the Vercel account, and
    // outside every cryptographic boundary in this system — and `e` here can be a driver error
    // whose message embeds bound parameters (tenant ids, key blobs). Silent 500s cost real
    // diagnosability; that trade is recorded here and in the report, not smuggled.
    void e;
    return err(500, GENERIC_ERROR);
  }
}

/**
 * The Sql handed to handlers when no route matched (the router answers 404 before any handler
 * runs). If it is ever called, dispatch and matching disagreed about the table — fail loudly
 * into the 500 path rather than let a handler run against nothing.
 */
const sqlUnreachable: Sql = async () => {
  throw new Error('a handler ran for a request that matched no route');
};

/* ------------------------------------------------------------------ *
 * Node transport
 * ------------------------------------------------------------------ */

/**
 * Read the raw body, bounded. The cap is checked as bytes arrive, so an oversized upload is
 * refused after ~1MB rather than buffered whole — parsing a 500MB body to learn it is too
 * large is the DoS. `MAX_PAYLOAD_BYTES` exactly: handleIngest rejects strictly-greater, so a
 * body of exactly the cap must survive this layer too.
 */
async function readBody(req: IncomingMessage, cap: number): Promise<Uint8Array | 'too_large'> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    total += buf.byteLength;
    if (total > cap) return 'too_large';
    chunks.push(buf);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * Node folds duplicate request headers into one comma-joined string for everything except a
 * short list it keeps as arrays. An array here becomes `undefined` — i.e. "not a single header
 * value" — which is exactly how verifyRequest treats a duplicated signature header.
 */
function singleValued(headers: IncomingHttpHeaders): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = Array.isArray(v) ? undefined : v;
  }
  return out;
}

function clientIpOf(headers: Record<string, string | undefined>): string | undefined {
  // Vercel sets both; x-forwarded-for may be a list, client-first.
  const real = headers['x-real-ip'];
  if (real) return real;
  const fwd = headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0]?.trim() : undefined;
}

export function createRequestListener(
  deps: EntryDeps,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    let out: RouterResponse;
    try {
      const url = new URL(req.url ?? '/', 'http://internal');
      const body = await readBody(req, MAX_PAYLOAD_BYTES);
      if (body === 'too_large') {
        out = err(413, 'payload too large');
      } else {
        const headers = singleValued(req.headers);
        // First value per name, matching how singleValued treats headers: a duplicated
        // parameter is not a single value and reads as absent-ish rather than attacker-picked.
        const query: Record<string, string | undefined> = {};
        for (const key of url.searchParams.keys()) {
          const values = url.searchParams.getAll(key);
          query[key] = values.length === 1 ? values[0] : undefined;
        }
        out = await handleHttpRequest(deps, {
          method: req.method ?? 'GET',
          path: url.pathname,
          headers,
          body,
          clientIp: clientIpOf(headers),
          query,
        });
      }
    } catch (e) {
      // A transport-level failure (aborted stream, unparsable URL). Same one sentence, same
      // no-logging rule as handleHttpRequest's catch.
      void e;
      out = err(500, GENERIC_ERROR);
    }

    res.statusCode = out.status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    // API responses carry ciphertext and auth decisions; nothing here is cacheable.
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    if (out.setCookie) res.setHeader('set-cookie', out.setCookie);
    res.end(JSON.stringify(out.body));
  };
}

/**
 * The default export is what Vercel's Node launcher invokes. Module scope holds the migration
 * MEMO (a promise, safe to hoist) and never a connection (db.ts Rule 1). The session seam gets
 * its real implementation here: `requireSessionFromSql`, over the per-request handle.
 */
const listener = createRequestListener({
  connectDb: () => connect(),
  ensureMigrated: createMigrator(),
  loadSchema: loadSchemaFromDisk,
  requireSession: requireSessionFromSql,
  env: process.env,
});

export default listener;
