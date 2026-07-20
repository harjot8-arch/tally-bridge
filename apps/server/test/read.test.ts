import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import {
  generateIdentity,
  makeAad,
  openSection,
  sealSection,
  unwrapWithPassphrase,
  wrapUnderPassphrase,
} from '@tally-bridge/crypto';
import { generateDeviceKeypair } from '@tally-bridge/protocol';
import type { SealedEnvelope, WrappedKey } from '@tally-bridge/core';
import { readDepsFromSql, type Row, type Sql } from '../src/db.ts';
import {
  handleGetWrappedKeys,
  handleListDevices,
  handleListSnapshots,
  handleRevokeDevice,
  type ReadDeps,
  type RequireSession,
} from '../src/read.ts';

/* ------------------------------------------------------------------ *
 * A fake Sql — an in-memory tagged-template stub
 * ------------------------------------------------------------------ */

/**
 * Enough Postgres to test the queries this app writes, and nothing more.
 *
 * It records every statement and every bound parameter, which lets the tests below assert two
 * different classes of thing: that the handlers apply the right access control, and that the
 * queries themselves bind values as PARAMETERS rather than splicing them into SQL text.
 */
function fakeSql(seed: { devices: Row[]; snapshots: Row[]; keys: Row[] }) {
  const devices = seed.devices.map((d) => ({ ...d }));
  const snapshots = seed.snapshots.map((s) => ({ ...s }));
  const keys = seed.keys.map((k) => ({ ...k }));
  const queries: Array<{ text: string; params: unknown[] }> = [];

  const sql: Sql = async (strings, ...params) => {
    const text = strings.join(' $? ').replace(/\s+/g, ' ').trim();
    queries.push({ text, params });

    const eq = (row: Row, col: string, i: number) => row[col] === params[i];

    if (/FROM snapshot/i.test(text)) {
      return snapshots.filter((r) => eq(r, 'tenant_id', 0));
    }
    if (/FROM wrapped_key/i.test(text)) {
      return keys.filter((r) => eq(r, 'tenant_id', 0));
    }
    if (/FROM device/i.test(text) && /tenant_id =/.test(text)) {
      return devices.filter((r) => eq(r, 'tenant_id', 0));
    }
    if (/FROM device/i.test(text) && /device_id =/.test(text)) {
      return devices.filter((r) => eq(r, 'device_id', 0));
    }
    if (/UPDATE device/i.test(text)) {
      const hit = devices.filter(
        (r) => r['device_id'] === params[0] && r['tenant_id'] === params[1] && r['revoked_at'] == null,
      );
      for (const r of hit) r['revoked_at'] = new Date('2026-07-16T10:00:00.000Z');
      return hit.map((r) => ({ device_id: r['device_id'] }));
    }
    throw new Error(`fakeSql: unhandled query: ${text}`);
  };

  return { sql, queries, devices, snapshots, keys };
}

/* ------------------------------------------------------------------ *
 * Fixture
 * ------------------------------------------------------------------ */

const TENANT_A = 'tnt_a';
const TENANT_B = 'tnt_b';
const DEVICE_A = 'dev_a';
const DEVICE_B = 'dev_b';

/** A value that exists ONLY inside the plaintext. If it ever appears in a response, we leaked. */
const SECRET_MARKER = 'ACME_TOTAL_RECEIVABLES_4242424242';
const PASSPHRASE = 'correct horse battery staple';

async function fixture() {
  const idA = await generateIdentity();
  const idB = await generateIdentity();
  // Envelopes are SIGNED by the uploading device as well as sealed to the identity key: a sealed
  // box needs only the identity PUBLIC key, which this server also holds, so without a signature
  // the server could fabricate financial data that passes every check the reader makes. These
  // fixtures are built the way a real Bridge builds them.
  const devA = await generateDeviceKeypair(DEVICE_A);
  const devB = await generateDeviceKeypair(DEVICE_B);

  const plaintext = {
    company: SECRET_MARKER,
    rows: [{ ledger: SECRET_MARKER, amount: -4_242_42 }],
  };

  const envA = await sealSection(
    plaintext,
    makeAad({
      tenantId: TENANT_A,
      deviceId: DEVICE_A,
      companyGuid: 'guid-acme',
      section: 'group_balance',
      asOf: '2026-07-16',
      snapshotTs: 1_752_600_000_000,
      seq: 1,
    }),
    idA.publicKey,
    devA.secretKey,
  );

  const envB = await sealSection(
    { company: 'other-tenant' },
    makeAad({
      tenantId: TENANT_B,
      deviceId: DEVICE_B,
      companyGuid: 'guid-other',
      section: 'group_balance',
      asOf: '2026-07-16',
      snapshotTs: 1_752_600_000_000,
      seq: 1,
    }),
    idB.publicKey,
    devB.secretKey,
  );

  const wrappedA = await wrapUnderPassphrase(idA.secretKey, PASSPHRASE);
  const wrappedB = await wrapUnderPassphrase(idB.secretKey, PASSPHRASE);

  const db = fakeSql({
    devices: [
      {
        device_id: DEVICE_A,
        tenant_id: TENANT_A,
        // Present in the table; must never reach a response body.
        public_key: Buffer.from('a-public-key'),
        label: 'Accounts PC',
        last_seen_ip: '49.36.1.1',
        last_seen_at: new Date('2026-07-16T09:00:00.000Z'),
        revoked_at: null,
        created_at: new Date('2026-01-01T00:00:00.000Z'),
      },
      {
        device_id: DEVICE_B,
        tenant_id: TENANT_B,
        public_key: Buffer.from('b-public-key'),
        label: 'Other Co PC',
        last_seen_ip: null,
        last_seen_at: null,
        revoked_at: null,
        created_at: new Date('2026-01-02T00:00:00.000Z'),
      },
    ],
    snapshots: [
      {
        tenant_id: TENANT_A,
        company_guid: 'guid-acme',
        section: 'group_balance',
        as_of: '2026-07-16',
        content_hash: envA.contentHash,
        envelope: envA,
        snapshot_ts: '1752600000000',
        seq: '1',
        bytes: 900,
        received_at: new Date('2026-07-16T09:00:00.000Z'),
      },
      {
        tenant_id: TENANT_B,
        company_guid: 'guid-other',
        section: 'group_balance',
        as_of: '2026-07-16',
        content_hash: envB.contentHash,
        envelope: envB,
        snapshot_ts: '1752600000000',
        seq: '1',
        bytes: 400,
        received_at: new Date('2026-07-16T09:00:00.000Z'),
      },
    ],
    keys: [
      { tenant_id: TENANT_A, kind: 'pass', blob: wrappedA, updated_at: new Date() },
      { tenant_id: TENANT_B, kind: 'pass', blob: wrappedB, updated_at: new Date() },
    ],
  });

  const session = (tenantId: string | undefined): RequireSession => async () => tenantId;

  const depsFor = (tenantId: string | undefined): ReadDeps =>
    readDepsFromSql(db.sql, session(tenantId));

  return { idA, idB, devA, devB, envA, plaintext, db, depsFor };
}

const H: Record<string, string | undefined> = { cookie: 'session=whatever' };

const dataOf = <T>(res: { body: { ok: true; data: T } | { ok: false; error: string } }): T => {
  assert.equal(res.body.ok, true, `expected ok, got ${JSON.stringify(res.body)}`);
  return (res.body as { ok: true; data: T }).data;
};

/* ------------------------------------------------------------------ *
 * The rule: no plaintext, and nothing that decrypts it
 * ------------------------------------------------------------------ */

/** Every string that appears anywhere in a response body, however deeply nested. */
function allStrings(v: unknown, out: string[] = []): string[] {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v) allStrings(x, out);
  else if (v && typeof v === 'object') for (const x of Object.values(v)) allStrings(x, out);
  return out;
}

test('snapshots: the response carries ciphertext and NOTHING that reads it', async () => {
  const { depsFor, idA } = await fixture();
  const res = await handleListSnapshots(H, depsFor(TENANT_A));
  const rows = dataOf(res);

  assert.equal(rows.length, 1);
  const env = rows[0]!.envelope;

  // The blob is here, and it is opaque.
  assert.equal(typeof env.ciphertext, 'string');
  assert.ok(env.ciphertext.length > 0);

  // The marker exists only in the plaintext. It must not appear in the response — not in a
  // field, not nested, not base64-decoded out of the ciphertext.
  const blob = JSON.stringify(res.body);
  assert.ok(!blob.includes(SECRET_MARKER), 'plaintext leaked into the response');
  assert.ok(
    !Buffer.from(env.ciphertext, 'base64').toString('binary').includes(SECRET_MARKER),
    'ciphertext is not actually encrypted',
  );

  // And the identity secret — the one key that opens it — is nowhere in the body.
  const secretB64 = Buffer.from(idA.secretKey).toString('base64');
  assert.ok(!blob.includes(secretB64), 'identity secret key leaked');
});

test('snapshots: the envelope survives verbatim — the browser can actually decrypt it', async () => {
  // The mirror of the test above. "Returns nothing useful" is easy to achieve by returning
  // garbage; this proves the response is both opaque to us AND sufficient for the owner.
  const { depsFor, idA, devA, plaintext } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));

  const opened = await openSection(rows[0]!.envelope, {
    identityPublicKey: idA.publicKey,
    identitySecretKey: idA.secretKey,
    // The reader states what it ASKED FOR, so the server cannot answer a different question with
    // a genuine envelope. The device roster is pinned, so a server that mints its own signing key
    // is not on it.
    expect: {
      tenantId: TENANT_A,
      companyGuid: 'guid-acme',
      section: 'group_balance',
      asOf: '2026-07-16',
    },
    trustedDevices: [{ deviceId: DEVICE_A, publicKey: devA.publicKey }],
  });
  assert.deepEqual(opened, plaintext);
});

test('snapshots: the wrong identity key cannot open the response', async () => {
  const { depsFor, idB, devA } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));

  await assert.rejects(() =>
    openSection(rows[0]!.envelope, {
      identityPublicKey: idB.publicKey,
      identitySecretKey: idB.secretKey,
      expect: {
        tenantId: TENANT_A,
        companyGuid: 'guid-acme',
        section: 'group_balance',
        asOf: '2026-07-16',
      },
      trustedDevices: [{ deviceId: DEVICE_A, publicKey: devA.publicKey }],
    }),
  );
});

test('no endpoint leaks a decryption key', async () => {
  const { depsFor, idA, idB } = await fixture();
  const deps = depsFor(TENANT_A);

  const bodies = [
    (await handleListSnapshots(H, deps)).body,
    (await handleGetWrappedKeys(H, deps)).body,
    (await handleListDevices(H, deps)).body,
    (await handleRevokeDevice(H, DEVICE_A, deps)).body,
  ];

  // Raw secret material, in the two encodings it could plausibly escape as.
  const forbidden = [
    Buffer.from(idA.secretKey).toString('base64'),
    Buffer.from(idA.secretKey).toString('hex'),
    Buffer.from(idB.secretKey).toString('base64'),
    PASSPHRASE,
    SECRET_MARKER,
  ];

  for (const body of bodies) {
    const haystack = JSON.stringify(body);
    for (const needle of forbidden) {
      assert.ok(!haystack.includes(needle), `leaked ${needle.slice(0, 12)}... in ${haystack.slice(0, 80)}`);
    }
    // Nothing may be named like a key that opens something.
    for (const s of Object.keys(flatten(body))) {
      assert.doesNotMatch(s, /^(secretKey|privateKey|plaintext|cek|kek|passphrase|dek)$/i);
    }
  }
});

function flatten(v: unknown, prefix = '', out: Record<string, unknown> = {}): Record<string, unknown> {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const [k, val] of Object.entries(v)) {
      out[k] = val;
      flatten(val, `${prefix}${k}.`, out);
    }
  } else if (Array.isArray(v)) {
    for (const x of v) flatten(x, prefix, out);
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Wrapped keys
 * ------------------------------------------------------------------ */

test('wrapped keys: returns blobs the passphrase opens and the server cannot', async () => {
  const { depsFor, idA } = await fixture();
  const keys = dataOf(await handleGetWrappedKeys(H, depsFor(TENANT_A)));

  assert.equal(keys.length, 1);
  const blob = keys[0] as WrappedKey;
  assert.equal(blob.kind, 'pass');

  // The KDF salt and parameters must travel with the blob, or its owner can never open it.
  assert.ok(blob.kdf, 'kdf params must be present');
  assert.equal(blob.kdf!.kdf, 'argon2id');
  assert.ok(blob.kdf!.salt.length > 0);

  // It opens with the passphrase...
  const sk = await unwrapWithPassphrase(blob, PASSPHRASE);
  assert.deepEqual(sk, idA.secretKey);

  // ...and with nothing else the server holds.
  await assert.rejects(() => unwrapWithPassphrase(blob, 'wrong passphrase'));

  // The blob itself is ciphertext: the key it wraps is not recoverable from the bytes on the wire.
  const onWire = JSON.stringify(blob);
  assert.ok(!onWire.includes(Buffer.from(idA.secretKey).toString('base64')));
});

test('wrapped keys: one tenant never receives another tenant\'s blob', async () => {
  const { depsFor, idB } = await fixture();
  const keys = dataOf(await handleGetWrappedKeys(H, depsFor(TENANT_A)));

  assert.equal(keys.length, 1);
  // Tenant B's blob would be grindable offline by tenant A with the same rig.
  const bWrapped = JSON.stringify(keys);
  assert.ok(!bWrapped.includes(Buffer.from(idB.secretKey).toString('base64')));
});

/* ------------------------------------------------------------------ *
 * Authentication
 * ------------------------------------------------------------------ */

test('unauthenticated reads are rejected — every endpoint, 401, no data', async () => {
  const { depsFor, db } = await fixture();
  const anon = depsFor(undefined);
  const before = db.queries.length;

  const responses = [
    await handleListSnapshots(H, anon),
    await handleGetWrappedKeys(H, anon),
    await handleListDevices(H, anon),
    await handleRevokeDevice(H, DEVICE_A, anon),
  ];

  for (const res of responses) {
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { ok: false, error: 'unauthorized' });
  }

  // Not merely filtered out of the body — never queried. An unauthenticated caller must not be
  // able to make this server touch the data at all.
  assert.equal(db.queries.length, before, 'an unauthenticated request must not hit the database');
});

test('unauthenticated reads are rejected with no session header at all', async () => {
  const { depsFor } = await fixture();
  const res = await handleListSnapshots({}, depsFor(undefined));
  assert.equal(res.status, 401);
});

test('the session is the ONLY source of the tenant id — a header cannot claim one', async () => {
  const { depsFor } = await fixture();

  // The classic bug: trusting a client-supplied tenant hint. `requireSession` returns TENANT_A,
  // so the response must be tenant A's regardless of what the request claims.
  const spoofed = {
    cookie: 'session=whatever',
    'x-tenant-id': TENANT_B,
    'x-tenant': TENANT_B,
  };

  const rows = dataOf(await handleListSnapshots(spoofed, depsFor(TENANT_A)));
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.companyGuid, 'guid-acme');
});

/* ------------------------------------------------------------------ *
 * Tenant isolation
 * ------------------------------------------------------------------ */

test('a session cannot read another tenant: snapshots, keys and devices are all scoped', async () => {
  const { depsFor } = await fixture();
  const a = depsFor(TENANT_A);

  const snaps = dataOf(await handleListSnapshots(H, a));
  assert.deepEqual(snaps.map((s) => s.companyGuid), ['guid-acme']);
  assert.ok(!JSON.stringify(snaps).includes('guid-other'));

  const devices = dataOf(await handleListDevices(H, a));
  assert.deepEqual(devices.map((d) => d.deviceId), [DEVICE_A]);

  const keys = dataOf(await handleGetWrappedKeys(H, a));
  assert.equal(keys.length, 1);
});

test('every tenant-scoped query BINDS the tenant id as a parameter', async () => {
  const { depsFor, db } = await fixture();
  const a = depsFor(TENANT_A);

  await handleListSnapshots(H, a);
  await handleGetWrappedKeys(H, a);
  await handleListDevices(H, a);

  assert.equal(db.queries.length, 3);
  for (const q of db.queries) {
    assert.match(q.text, /WHERE tenant_id = \$\?/, `not parameterized: ${q.text}`);
    assert.deepEqual(q.params, [TENANT_A]);
    // The value must never be spliced into the SQL text.
    assert.ok(!q.text.includes(TENANT_A), `tenant id interpolated into SQL: ${q.text}`);
  }
});

test('an injection-shaped tenant id is bound, not executed', async () => {
  const { depsFor, db } = await fixture();
  const evil = `x'; DROP TABLE snapshot; --`;

  const rows = dataOf(await handleListSnapshots(H, depsFor(evil)));
  assert.deepEqual(rows, []);

  const q = db.queries[0]!;
  assert.deepEqual(q.params, [evil]);
  assert.ok(!q.text.includes('DROP TABLE'));
});

/* ------------------------------------------------------------------ *
 * Devices and revocation
 * ------------------------------------------------------------------ */

test('devices: the list carries what the owner needs to choose, and no key material', async () => {
  const { depsFor } = await fixture();
  const devices = dataOf(await handleListDevices(H, depsFor(TENANT_A)));

  const d = devices[0]!;
  assert.equal(d.deviceId, DEVICE_A);
  assert.equal(d.label, 'Accounts PC');
  assert.equal(d.lastSeenIp, '49.36.1.1');
  assert.equal(d.revokedAt, undefined);
  assert.equal(d.lastSeenAt, '2026-07-16T09:00:00.000Z');

  // public_key is in the row the database returned. It must not be in the response: harmless,
  // but a field no screen renders is a field nobody audits.
  assert.ok(!Object.keys(d).includes('publicKey'));
  assert.ok(!JSON.stringify(devices).includes('public'));
});

test('revoke: marks the device revoked and shows up in the list', async () => {
  const { depsFor } = await fixture();
  const a = depsFor(TENANT_A);

  const res = await handleRevokeDevice(H, DEVICE_A, a);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { ok: true, data: { deviceId: DEVICE_A, revoked: true } });

  const devices = dataOf(await handleListDevices(H, a));
  assert.ok(devices[0]!.revokedAt, 'revoked_at must be set — this is what stops future uploads');
});

test('revoke: a device cannot be revoked by another tenant, and gets a 404, not a 403', async () => {
  const { depsFor, db } = await fixture();

  // Tenant A tries to disable tenant B's uploader: a cross-tenant denial of service.
  const res = await handleRevokeDevice(H, DEVICE_B, depsFor(TENANT_A));
  assert.equal(res.status, 404);
  assert.deepEqual(res.body, { ok: false, error: 'device not found' });

  // The device is untouched.
  assert.equal(db.devices[1]!['revoked_at'], null);
});

test('revoke: an unknown device and another tenant\'s device are indistinguishable', async () => {
  const { depsFor } = await fixture();
  const a = depsFor(TENANT_A);

  const unknown = await handleRevokeDevice(H, 'dev_does_not_exist', a);
  const foreign = await handleRevokeDevice(H, DEVICE_B, a);

  // Identical answers, or this endpoint is an oracle for enumerating device ids.
  assert.deepEqual(unknown, foreign);
});

test('revoke: no UPDATE is issued for a device the session does not own', async () => {
  const { depsFor, db } = await fixture();
  await handleRevokeDevice(H, DEVICE_B, depsFor(TENANT_A));

  assert.ok(
    !db.queries.some((q) => /UPDATE device/i.test(q.text)),
    'ownership must be checked before the write, not after',
  );
});

test('revoke: the UPDATE is scoped by tenant as well as device', async () => {
  const { depsFor, db } = await fixture();
  await handleRevokeDevice(H, DEVICE_A, depsFor(TENANT_A));

  const update = db.queries.find((q) => /UPDATE device/i.test(q.text))!;
  assert.match(update.text, /device_id = \$\? AND tenant_id = \$\?/);
  assert.deepEqual(update.params, [DEVICE_A, TENANT_A]);
});

test('revoke: is idempotent — a second click is not an error', async () => {
  const { depsFor } = await fixture();
  const a = depsFor(TENANT_A);

  const first = await handleRevokeDevice(H, DEVICE_A, a);
  const second = await handleRevokeDevice(H, DEVICE_A, a);

  assert.equal(first.status, 200);
  assert.equal(second.status, 200, 'a panicking owner must not be told the button failed');
});

test('revoke: rejects an empty device id', async () => {
  const { depsFor } = await fixture();
  const res = await handleRevokeDevice(H, '', depsFor(TENANT_A));
  assert.equal(res.status, 400);
});

/* ------------------------------------------------------------------ *
 * Row mapping
 * ------------------------------------------------------------------ */

test('rows: bigint columns arrive as strings and must not be shipped as strings', async () => {
  // snapshot_ts and seq are BIGINT; the driver hands them back as strings to avoid silent
  // precision loss. The dashboard compares snapshotTs numerically for its freshness check, and
  // '900' < '1000' is false when compared as strings.
  const { depsFor } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));

  assert.equal(typeof rows[0]!.snapshotTs, 'number');
  assert.equal(rows[0]!.snapshotTs, 1_752_600_000_000);
  assert.equal(typeof rows[0]!.seq, 'number');
});

test('rows: as_of stays the stored calendar date, whatever the server zone', async () => {
  // A DATE parsed into a Date and re-serialized through toISOString() moves a day backwards on
  // a UTC-hosted function for an IST-entered financial-year boundary.
  const { depsFor } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));
  assert.equal(rows[0]!.asOf, '2026-07-16');
});

test('rows: the snapshot projection ships exactly the documented fields', async () => {
  const { depsFor } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));

  assert.deepEqual(Object.keys(rows[0]!).sort(), [
    'asOf',
    'bytes',
    'companyGuid',
    'contentHash',
    'envelope',
    'receivedAt',
    'section',
    'seq',
    'snapshotTs',
  ]);
  assert.deepEqual(Object.keys(rows[0]!.envelope).sort(), [
    'aad',
    'ciphertext',
    'contentHash',
    'nonce',
    // The device's signature over the envelope. It MUST reach the browser: it is what proves the
    // envelope came from a Bridge and not from this server, which holds the identity public key
    // and could otherwise seal a box of its own invention. Shipping it leaks nothing — a
    // signature is verified with a public key, not opened with one.
    'sealedCek',
    'sig',
  ]);
});

test('rows: a column added to the table does not silently become a response field', async () => {
  // The regression this guards: someone adds `plaintext_cache` to `snapshot` and a `SELECT *`
  // plus a spread ships it to every browser with no diff in db.ts or read.ts to review.
  const { db } = await fixture();
  (db.snapshots[0] as Row)['plaintext_cache'] = SECRET_MARKER;

  const deps = readDepsFromSql(db.sql, async () => TENANT_A);
  const res = await handleListSnapshots(H, deps);

  assert.ok(!JSON.stringify(res.body).includes(SECRET_MARKER));
});

test('NOTHING IN THIS SERVER LOGS — a Vercel log is a second copy of the database', async () => {
  // Vercel captures stdout/stderr from every function into a retained, searchable log that is
  // read by whoever holds the Vercel account, is not covered by any of the crypto in this
  // system, and outlives the request by weeks. One `console.error(err)` in a catch block where
  // `err` closes over the request body writes ciphertext there; one `console.log({ body })` in
  // the register route writes BOOTSTRAP_SECRET there in plaintext.
  //
  // No handler here logs today. This test is what keeps it that way — it is far easier to add a
  // debug line than to notice one in review, and the failure is invisible at runtime: the
  // endpoint behaves perfectly while quietly copying secrets somewhere else.
  // BOTH source trees, because "this server" is the Vercel FUNCTION, not the apps/server folder.
  // This scan used to cover apps/server/src alone, and that boundary is not where the risk stops:
  // packages/protocol runs INSIDE the same function on the same request, and `verifyRequest`
  // takes the raw body as an argument. A single `console.error('verify', request.body)` in
  // signing.ts therefore writes CIPHERTEXT to the retained Vercel log from a file this test was
  // not looking at — verified by adding exactly that line and watching this test stay green.
  // packages/crypto is excluded on purpose: it does not run in the function.
  const dirs = [new URL('../src/', import.meta.url), new URL('../../../packages/protocol/src/', import.meta.url)];
  let scanned = 0;

  for (const dir of dirs) {
    const files = (await readdir(dir)).filter((f) => f.endsWith('.ts'));
    assert.ok(files.length > 0, `expected to be scanning a real source directory: ${dir.pathname}`);

    for (const file of files) {
      const src = await readFile(new URL(file, dir), 'utf8');
      const stripped = src
        .replace(/\/\*[\s\S]*?\*\//g, '') // block comments: they discuss logging on purpose
        .replace(/^\s*\/\/.*$/gm, '');
      assert.doesNotMatch(stripped, /\bconsole\s*\./, `${file} writes to the Vercel log`);
      assert.doesNotMatch(stripped, /process\.(stdout|stderr)\b/, `${file} writes to the Vercel log`);
      scanned++;
    }
  }
  assert.ok(scanned >= 7, `expected to be scanning both source trees, saw ${scanned} files`);
});

test('the envelope AAD is the outer edge of what leaves this server', async () => {
  // Documented, deliberate metadata leakage. If this list ever grows, it was not an accident
  // and someone had to change this test.
  const { depsFor } = await fixture();
  const rows = dataOf(await handleListSnapshots(H, depsFor(TENANT_A)));
  const aad = rows[0]!.envelope.aad as unknown as Record<string, unknown>;

  assert.deepEqual(Object.keys(aad).sort(), [
    'asOf',
    'companyGuid',
    'deviceId',
    'schemaVer',
    'section',
    'seq',
    'snapshotTs',
    'tenantId',
    'v',
  ]);
  // Metadata, all of it. No amounts, no ledger names.
  assert.ok(!allStrings(aad).includes(SECRET_MARKER));
});
