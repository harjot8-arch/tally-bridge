import { readFile } from 'node:fs/promises';
import type { SqlTransaction } from './db.ts';

/**
 * The migration runner.
 *
 * WHY THIS EXISTS AT ALL. `POST /v13/deployments` does not run migrations. Nothing does. The
 * desktop app provisions a Vercel project and a Neon database and pushes a deploy; the deploy
 * reports success, the URL is live, and the very first request dies on `relation "device" does
 * not exist`. To the owner — who has just watched a green "Deployed" tick — that is our bug, at
 * the exact moment their trust is thinnest. There is no CI step to hang a migration off,
 * because there is no CI: the client's Vercel account is the deploy target. So the schema is
 * applied lazily, on the first request that needs it, by the application itself.
 *
 * WHY THE LOCK. A cold start is not one process. A first request that fans out, or a deploy
 * that receives two requests in the same second, boots several function instances at once and
 * every one of them will try to migrate. `CREATE TABLE IF NOT EXISTS` is NOT safe under
 * concurrency — the existence check and the create are not atomic, so two instances racing
 * through it produce `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`
 * from deep inside Postgres's catalog. The `IF NOT EXISTS` reads as protection and is not. The
 * advisory lock is what actually serializes them; `IF NOT EXISTS` is then what makes the
 * loser's pass a no-op instead of an error.
 *
 * WHY `pg_advisory_xact_lock` AND NOT `pg_advisory_lock`. This is the subtle one, and getting it
 * wrong yields code that looks locked and is not. A plain `pg_advisory_lock` is held by the
 * SESSION. Neon's HTTP driver has no session: every query is an independent POST that gets
 * whatever connection the proxy hands it, and the lock is released the moment that query
 * returns. Taking `pg_advisory_lock` in one HTTP query and running DDL in the next would
 * acquire a lock, drop it immediately, and then migrate unprotected — a race with a comment
 * above it claiming otherwise. `pg_advisory_xact_lock` is scoped to a TRANSACTION, and Neon's
 * HTTP transaction runs its whole batch on one connection inside one BEGIN/COMMIT. So the lock
 * is taken as the first statement of the batch, held across the DDL, and released by the commit
 * — including if the batch throws, which is the other half of why the xact form is right: a
 * session lock leaked by a crashed instance would block every future cold start until the
 * connection timed out.
 *
 * WHY THE MEMO. Warm instances serve many requests. Migrating on each one would add a
 * round-trip to every request forever to fix a problem that exists for one request. The
 * migrator remembers the in-flight promise, so concurrent requests on one instance await the
 * same migration and later requests skip it entirely — and it forgets a FAILED migration, so a
 * transient database blip does not poison an instance into serving errors for the rest of its
 * life.
 */

/**
 * The advisory lock key. Arbitrary but FIXED FOREVER: the lock only works if every instance,
 * across every version, picks the same number. Never make this configurable, never derive it
 * from anything that could vary (a URL, a deployment id, a hash of the schema) — two instances
 * computing different keys hold different locks and are not serialized at all, which is exactly
 * the bug this file exists to prevent, now with a lock to make it look handled.
 */
export const MIGRATION_LOCK_KEY = 8_312_004_771_205_931n;

/** Emitted as the first statement of the migration batch. Exported for tests to assert on. */
export const LOCK_STATEMENT = `SELECT pg_advisory_xact_lock(${MIGRATION_LOCK_KEY})`;

export interface MigrateDeps {
  /** A batch runner with ONE-CONNECTION, ONE-TRANSACTION semantics. See db.ts. */
  transaction: SqlTransaction;
  /** Injected so tests need neither a filesystem nor a database. */
  loadSchema: () => Promise<string>;
}

/**
 * Apply the schema, once, under the lock.
 *
 * Prefer `createMigrator` in a request path — this is the unmemoized primitive.
 */
export async function runMigrations(deps: MigrateDeps): Promise<void> {
  const statements = splitStatements(await deps.loadSchema());
  if (statements.length === 0) return;

  // The lock MUST be the first statement in the same batch as the DDL. Splitting them into two
  // transactions releases the lock in between and silently unprotects the migration.
  await deps.transaction([LOCK_STATEMENT, ...statements]);
}

export type Migrator = (deps: MigrateDeps) => Promise<void>;

/**
 * Wrap `runMigrations` in a per-instance memo.
 *
 * Create ONE of these at module scope in the route file — it holds a promise, never a
 * connection, so it is safe to hoist in a way that a database handle is not. Pass it the
 * request's `Db` on each call.
 */
export function createMigrator(): Migrator {
  let inflight: Promise<void> | undefined;

  return function ensureMigrated(deps: MigrateDeps): Promise<void> {
    // Concurrent requests on this instance join the same promise rather than each starting a
    // migration and fighting each other for the lock.
    if (inflight) return inflight;

    inflight = runMigrations(deps).catch((e: unknown) => {
      // Forget the failure so the next request retries. Caching a rejected promise would turn
      // one bad round-trip into an instance that is permanently broken but perfectly healthy
      // from the platform's point of view.
      inflight = undefined;
      throw e;
    });

    return inflight;
  };
}

/**
 * Split a SQL file into statements.
 *
 * Neon's HTTP endpoint uses the extended query protocol, which permits exactly one command per
 * message — posting the whole file rings up `cannot insert multiple commands into a prepared
 * statement`. So the file has to be split here.
 *
 * This is deliberately a DUMB splitter: strip `--` comments, split on `;`. It is correct for
 * schema.sql, which contains no semicolon inside any string literal, dollar-quoted body, or
 * identifier. It would be wrong for a file that did. If you ever add a trigger, a `DO $$ ... $$`
 * block, or a default containing `;`, this function is the thing that breaks — and it will
 * break loudly at boot, not subtly at runtime. Fix it then; do not pre-build a SQL parser now.
 */
export function splitStatements(sql: string): string[] {
  return sql
    .split('\n')
    .map((line) => stripLineComment(line))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function stripLineComment(line: string): string {
  const i = line.indexOf('--');
  return i === -1 ? line : line.slice(0, i);
}

/**
 * Read schema.sql from disk, next to this module.
 *
 * `import.meta.url` rather than `process.cwd()`: the working directory of a serverless function
 * is not the directory of its code, and a cwd-relative path resolves on a laptop and throws
 * ENOENT on Vercel.
 *
 * NOTE FOR THE ROUTE AUTHOR: a bundler traces `import`s, not `readFile` calls, so schema.sql
 * can be left out of the deployment even though this path is correct. Confirm the file ships
 * (Next.js: `outputFileTracingIncludes`). If that ever becomes a fight, the fix is to inline
 * the schema as a `.ts` string constant and pass it as `loadSchema` — which is exactly why
 * `loadSchema` is injected and not hardcoded.
 */
export async function loadSchemaFromDisk(): Promise<string> {
  return readFile(new URL('./schema.sql', import.meta.url), 'utf8');
}
