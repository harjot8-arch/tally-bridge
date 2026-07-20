import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  LOCK_STATEMENT,
  MIGRATION_LOCK_KEY,
  createMigrator,
  loadSchemaFromDisk,
  runMigrations,
  splitStatements,
  type MigrateDeps,
} from '../src/migrate.ts';

/**
 * A fake Postgres, just real enough to catch the bugs that matter.
 *
 * It models the three things the migration runner's correctness actually rests on:
 *   1. Advisory locks are held for the length of a TRANSACTION and are mutually exclusive.
 *   2. `CREATE TABLE` without `IF NOT EXISTS` blows up on a table that already exists — this is
 *      what makes a lost race visible instead of silently passing.
 *   3. Statements execute in order.
 *
 * The point is that a test which only counts calls proves nothing about concurrency. This one
 * fails if the lock is not actually held across the DDL.
 */
function fakePostgres() {
  const tables = new Set<string>();
  const log: string[] = [];
  let lockHolder: number | undefined;
  let lockWaits = 0;
  let batches = 0;
  /** Set of statements to fail on, for the retry test. */
  let failNext: string | undefined;

  const waiters: Array<() => void> = [];

  async function acquire(key: bigint, who: number): Promise<void> {
    assert.equal(key, MIGRATION_LOCK_KEY, 'migration must use the fixed lock key');
    while (lockHolder !== undefined) {
      lockWaits++;
      await new Promise<void>((r) => waiters.push(r));
    }
    lockHolder = who;
  }

  function release(): void {
    lockHolder = undefined;
    const next = waiters.shift();
    if (next) next();
  }

  let ids = 0;

  const transaction = async (statements: readonly string[]): Promise<void> => {
    const who = ++ids;
    batches++;
    let holding = false;
    try {
      for (const s of statements) {
        log.push(s);

        const lock = /pg_advisory_xact_lock\((\d+)\)/.exec(s);
        if (lock?.[1]) {
          await acquire(BigInt(lock[1]), who);
          holding = true;
          continue;
        }

        if (failNext !== undefined && s.includes(failNext)) {
          failNext = undefined;
          throw new Error('connection reset by peer');
        }

        const create = /CREATE TABLE (IF NOT EXISTS )?(\w+)/i.exec(s);
        if (create) {
          const [, ifNotExists, name] = create;
          if (!name) continue;
          if (tables.has(name)) {
            // Exactly what Postgres does, from inside the catalog, when two instances race.
            if (!ifNotExists) {
              throw new Error(
                `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`,
              );
            }
            continue;
          }
          tables.add(name);
        }
      }
    } finally {
      // An xact lock is released by COMMIT *or* ROLLBACK. Model both.
      if (holding) release();
    }
  };

  return {
    transaction,
    tables,
    log,
    stats: () => ({ batches, lockWaits }),
    isLocked: () => lockHolder !== undefined,
    failOn: (fragment: string) => {
      failNext = fragment;
    },
  };
}

const SCHEMA = `
-- a comment; with a semicolon-looking thing in prose
CREATE TABLE IF NOT EXISTS device (
  device_id TEXT PRIMARY KEY
);

CREATE INDEX IF NOT EXISTS ix_device_tenant ON device (tenant_id);

CREATE TABLE IF NOT EXISTS snapshot (
  tenant_id TEXT NOT NULL
);
`;

const depsFor = (pg: ReturnType<typeof fakePostgres>, schema = SCHEMA): MigrateDeps => ({
  transaction: pg.transaction,
  loadSchema: async () => schema,
});

test('migrate: applies the schema', async () => {
  const pg = fakePostgres();
  await runMigrations(depsFor(pg));

  assert.deepEqual([...pg.tables].sort(), ['device', 'snapshot']);
});

test('migrate: takes the advisory lock as the FIRST statement, in the same batch as the DDL', async () => {
  const pg = fakePostgres();
  await runMigrations(depsFor(pg));

  // One batch: lock and DDL in one transaction. Two batches would mean the lock was released
  // before the DDL ran — the exact bug that a session-scoped lock over an HTTP driver produces.
  assert.equal(pg.stats().batches, 1);
  assert.equal(pg.log[0], LOCK_STATEMENT);
  assert.match(String(pg.log[0]), /pg_advisory_xact_lock/);
});

test('migrate: uses an xact lock, never a session lock', () => {
  // A session lock over Neon's HTTP driver is released the instant its query returns, so it
  // would leave the DDL unprotected while looking locked.
  assert.doesNotMatch(LOCK_STATEMENT, /pg_advisory_lock\(/);
  assert.match(LOCK_STATEMENT, /pg_advisory_xact_lock\(/);
});

test('migrate: is idempotent — running twice changes nothing and does not throw', async () => {
  const pg = fakePostgres();
  await runMigrations(depsFor(pg));
  await runMigrations(depsFor(pg));
  await runMigrations(depsFor(pg));

  assert.deepEqual([...pg.tables].sort(), ['device', 'snapshot']);
});

test('migrate: concurrent cold starts do not double-run — the lock serializes them', async () => {
  const pg = fakePostgres();

  // Eight separate function instances booting at once. Each has its own memo, so the memo
  // cannot be what saves us here — only the lock can.
  await Promise.all(Array.from({ length: 8 }, () => createMigrator()(depsFor(pg))));

  assert.deepEqual([...pg.tables].sort(), ['device', 'snapshot']);
  // Every instance ran a batch...
  assert.equal(pg.stats().batches, 8);
  // ...but they queued behind each other rather than interleaving.
  assert.ok(pg.stats().lockWaits > 0, 'expected contention on the advisory lock');
  assert.equal(pg.isLocked(), false, 'lock must be released when the transaction ends');
});

test('migrate: an unprotected concurrent migration WOULD corrupt — proving the lock is load-bearing', async () => {
  // Same fake, same schema, but with `IF NOT EXISTS` removed and no lock: this is what the
  // naive implementation does. It must fail, or the test above proves nothing.
  const pg = fakePostgres();
  const naive = SCHEMA.replace(/IF NOT EXISTS /g, '');
  const statements = splitStatements(naive);

  const results = await Promise.allSettled(
    Array.from({ length: 4 }, () => pg.transaction(statements)),
  );

  assert.ok(
    results.some((r) => r.status === 'rejected'),
    'concurrent CREATE TABLE without a lock must collide',
  );
});

test('migrate: the memo runs it once per warm instance', async () => {
  const pg = fakePostgres();
  const ensure = createMigrator();

  await ensure(depsFor(pg));
  await ensure(depsFor(pg));
  await ensure(depsFor(pg));

  assert.equal(pg.stats().batches, 1, 'a warm instance must not re-migrate on every request');
});

test('migrate: concurrent requests on ONE instance join the same in-flight migration', async () => {
  const pg = fakePostgres();
  const ensure = createMigrator();

  await Promise.all([ensure(depsFor(pg)), ensure(depsFor(pg)), ensure(depsFor(pg))]);

  assert.equal(pg.stats().batches, 1);
});

test('migrate: a failed migration is not memoized — the next request retries', async () => {
  const pg = fakePostgres();
  const ensure = createMigrator();

  pg.failOn('CREATE TABLE IF NOT EXISTS snapshot');
  await assert.rejects(() => ensure(depsFor(pg)), /connection reset/);

  // A cached rejected promise would make this instance permanently broken while looking healthy.
  await ensure(depsFor(pg));
  assert.ok(pg.tables.has('snapshot'));
  assert.equal(pg.isLocked(), false, 'a throwing batch must still release the lock');
});

test('migrate: the lock key is a fixed constant', () => {
  // Deriving this from anything variable (a URL, a deploy id, a schema hash) means two
  // instances take different locks and are not serialized at all.
  assert.equal(typeof MIGRATION_LOCK_KEY, 'bigint');
  assert.equal(MIGRATION_LOCK_KEY, 8_312_004_771_205_931n);
  // Must fit in a Postgres bigint.
  assert.ok(MIGRATION_LOCK_KEY < 9_223_372_036_854_775_807n);
});

test('splitStatements: strips comments and empty fragments', () => {
  const out = splitStatements(SCHEMA);
  assert.equal(out.length, 3);
  assert.ok(out.every((s) => !s.includes('--')));
  assert.ok(out.every((s) => s.trim().length > 0));
  assert.match(String(out[0]), /^CREATE TABLE IF NOT EXISTS device/);
});

/**
 * The splitter is deliberately dumb: strip `--`, split on `;`. Its own comment says it is
 * correct for schema.sql "which contains no semicolon inside any string literal, dollar-quoted
 * body, or identifier", and that it would break LOUDLY on a file that did.
 *
 * Both halves of that are claims, and a claim about a file that someone will edit later is worth
 * exactly as much as the test that pins it. These three tests are that test.
 */

test('splitStatements: the shipped schema.sql actually meets the splitter’s precondition', () => {
  // The guard that matters. The splitter is safe for the schema we ship TODAY. Nothing stops
  // someone adding `DEFAULT 'a;b'` in six months — at which point the schema silently splits
  // into fragments, and the first place anyone finds out is a customer's first request against
  // a half-created database. This fails in CI instead.
  const schema = readFileSync(new URL('../src/schema.sql', import.meta.url), 'utf8');

  // Comments come off first — prose is allowed to contain apostrophes and semicolons, and the
  // splitter strips it before it ever sees it. What is being checked is the CODE.
  const code = schema
    .split('\n')
    .map((line) => (line.includes('--') ? line.slice(0, line.indexOf('--')) : line))
    .join('\n');

  for (const [i, line] of code.split('\n').entries()) {
    const quotes = (line.match(/'/g) ?? []).length;
    assert.equal(quotes % 2, 0, `line ${i + 1}: unbalanced quote — a string spans lines here: ${line}`);
    assert.ok(!line.includes('$$'), `line ${i + 1}: dollar quoting is not supported by splitStatements`);
  }

  // Every single-quoted string in the code, checked for the two characters that break the split.
  for (const literal of code.match(/'[^']*'/g) ?? []) {
    assert.ok(!literal.includes(';'), `semicolon inside a string literal: ${literal}`);
    assert.ok(!literal.includes('--'), `comment marker inside a string literal: ${literal}`);
  }

  // And the statements that come out are individually well-formed in the one way we can cheaply
  // check: quotes balance. An unbalanced quote is the signature of a bad split.
  for (const s of splitStatements(schema)) {
    assert.equal((s.match(/'/g) ?? []).length % 2, 0, `bad split produced: ${s.slice(0, 60)}`);
  }
});

test('splitStatements: a semicolon in a string literal breaks LOUDLY, as documented', () => {
  // The comment's escape hatch is "it will break loudly at boot, not subtly at runtime". That is
  // only tolerable if it is TRUE, so: verify it. Both fragments must be visibly broken SQL —
  // unbalanced quotes — rather than two statements Postgres would happily run.
  const out = splitStatements(`INSERT INTO t (note) VALUES ('a;b') ON CONFLICT DO NOTHING;`);

  assert.equal(out.length, 2, 'the dumb splitter does split here — this is the known limitation');
  for (const fragment of out) {
    assert.equal(
      (fragment.match(/'/g) ?? []).length % 2,
      1,
      `fragment must be obviously broken, not silently valid: ${fragment}`,
    );
  }
});

test('splitStatements: a dollar-quoted body breaks LOUDLY too', () => {
  const out = splitStatements(`CREATE FUNCTION f() RETURNS int AS $$ SELECT 1; $$ LANGUAGE sql;`);

  // Torn into an unterminated dollar quote and an orphan tail. Postgres rejects both on sight.
  assert.ok(out.length > 1, 'the known limitation: dollar quoting is not understood');
  assert.match(String(out[0]), /\$\$/);
  assert.ok(!String(out[0]).endsWith('$$'), 'the opening $$ is left unterminated — a loud error');
});

test('splitStatements: an empty schema produces no batch', async () => {
  const pg = fakePostgres();
  await runMigrations(depsFor(pg, '-- nothing but a comment\n\n'));
  assert.equal(pg.stats().batches, 0, 'do not open a transaction to run nothing');
});

test('migrate: the REAL schema.sql applies, is idempotent, and every statement is re-runnable', async () => {
  // The unit tests above use a toy schema. This one runs the file we actually ship — it is the
  // test that catches someone adding a `CREATE TABLE` without `IF NOT EXISTS`, whose second run
  // would break every cold start after the first deploy.
  const schema = await loadSchemaFromDisk();
  const statements = splitStatements(schema);

  assert.ok(statements.length > 5, 'expected the real schema to have several statements');

  for (const s of statements) {
    if (/^CREATE TABLE/i.test(s)) {
      assert.match(s, /CREATE TABLE IF NOT EXISTS/i, `not re-runnable: ${s.slice(0, 60)}`);
    }
    if (/^CREATE INDEX/i.test(s)) {
      assert.match(s, /CREATE INDEX IF NOT EXISTS/i, `not re-runnable: ${s.slice(0, 60)}`);
    }
    if (/^INSERT/i.test(s)) {
      assert.match(s, /ON CONFLICT/i, `not re-runnable: ${s.slice(0, 60)}`);
    }
  }

  const pg = fakePostgres();
  await runMigrations({ transaction: pg.transaction, loadSchema: async () => schema });
  await runMigrations({ transaction: pg.transaction, loadSchema: async () => schema });

  for (const expected of ['device', 'wrapped_key', 'seen_nonce', 'snapshot', 'upload_window', 'bootstrap']) {
    assert.ok(pg.tables.has(expected), `missing table ${expected}`);
  }
});

test('migrate: the real schema survives concurrent cold starts', async () => {
  const schema = await loadSchemaFromDisk();
  const pg = fakePostgres();
  const deps = { transaction: pg.transaction, loadSchema: async () => schema };

  await Promise.all(Array.from({ length: 5 }, () => createMigrator()(deps)));

  assert.ok(pg.tables.has('snapshot'));
  assert.equal(pg.isLocked(), false);
});
