/**
 * THE END-TO-END SIMULATION.
 *
 *   fake Tally  ->  probeCapabilities  ->  buildCycle  ->  real crypto (seal)
 *        ->  real Ed25519 signing  ->  real handleIngest  ->  in-memory store
 *        ->  openSection with the identity SECRET key  ->  assert  ->  cards
 *
 * Everything between the two ends is the REAL module. There are exactly two fakes, and they are
 * the two things we cannot have on this machine:
 *
 *   1. Tally itself      — an HTTP server on a random port speaking the TDL dialect
 *                          `Bill` + `$LedgerName` (the "nobody predicted it" dialect, so the
 *                          runtime prober has to actually converge rather than luck into the
 *                          documented default).
 *   2. Vercel/Neon       — an HTTP server whose handler IS `handleIngest` from
 *                          apps/server/src/ingest.ts, backed by a Map.
 *
 * Why this script exists: 457 unit tests all pass while testing each module against its own
 * idea of the data. This is the only test that makes the modules agree with EACH OTHER. The
 * numbers that come out of the far end are compared against the numbers the fake Tally served,
 * and the two must be equal or the product is lying to somebody.
 *
 * Run:  node --experimental-strip-types scripts/e2e-simulation.ts
 *       (add --verbose to dump the resolved quirks and every sync event)
 *
 * Exits 0 only if every stage agrees. Any disagreement is a hard failure with a loud message.
 */

import http from 'node:http';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { TallyTransport, probeCapabilities } from '@tally-bridge/tally';
import { generateIdentity, openSection } from '@tally-bridge/crypto';
import { generateDeviceKeypair } from '@tally-bridge/protocol';
import { SeqCounter, SyncStore, type SyncEvent } from '@tally-bridge/sync';
import type { SealedEnvelope, Section } from '@tally-bridge/core';
import {
  ageingCard,
  balanceSheetTree,
  cashBankCard,
  formatMoney,
  profitCard,
  salesTrendCard,
  stockCard,
} from '@tally-bridge/viewmodel';

import { buildCycle } from '../apps/bridge/src/main/cycle.ts';
import { handleIngest, type IngestDeps } from '../apps/server/src/ingest.ts';

const VERBOSE = process.argv.includes('--verbose');

// ============================================================ the books
//
// One realistic Indian SMB, in THE convention: Dr negative, Cr positive (see ARCHITECTURE.md).
// Assets (cash, bank, stock) are Dr and therefore arrive NEGATIVE; the card layer flips them.
// This fixture is the single source of truth for every expectation below — the assertions are
// derived from it rather than hardcoded, so they cannot drift away from what the fake serves.

const COMPANY = {
  name: 'Shree Ganesh Traders',
  guid: 'a1b2c3d4-0000-4f00-9000-abcdef123456',
  state: 'Maharashtra',
  booksFrom: '2026-04-01',
  booksFromTally: '20260401',
  lastVoucher: '20260716',
  altMstId: 1200,
  altVchId: 3400,
} as const;

const AS_OF = '2026-07-16';

/**
 * `wire` is what the fake writes into the XML (escaped / entity-encoded, exactly as Tally would);
 * `name` is what MUST come out the far end after the codec, crypto, and the wire round trip.
 * The two differing is the whole point: it proves the codec's unescaping survives the pipeline.
 */
interface Party {
  wire: string;
  name: string;
}

const P_AB: Party = { wire: 'A &amp; B Traders &lt;Mumbai&gt;', name: 'A & B Traders <Mumbai>' };
const P_GANESH: Party = { wire: 'श्री गणेश ट्रेडर्स', name: 'श्री गणेश ट्रेडर्स' };
const P_CAFE: Party = { wire: 'Caf&#233; Traders', name: 'Café Traders' };
const P_ZED: Party = { wire: 'Zed Enterprises', name: 'Zed Enterprises' };
const P_STEEL: Party = { wire: 'Maharashtra Steel Co', name: 'Maharashtra Steel Co' };
const P_TATA: Party = { wire: 'Tata Chemicals Ltd', name: 'Tata Chemicals Ltd' };

interface BillFixture {
  party: Party;
  billDate: string;
  creditDays: number;
  /** Signed decimal string, exactly as `expr.amount` would render it. Dr negative. */
  amount: string;
  daysSinceBill: number;
  isAdvance?: boolean;
  /** What `bucketFor` must decide. Stated independently so a bucketing regression is caught. */
  expectBucket: string;
}

/** Receivables are Dr -> negative. The card layer flips them so "who owes me" reads positive. */
const RECEIVABLES: BillFixture[] = [
  // 196 days old, 30 days credit -> 166 overdue -> 91_180
  { party: P_AB, billDate: '2026-01-01', creditDays: 30, amount: '-125000.00', daysSinceBill: 196, expectBucket: '91_180' },
  // 45 days old, 45 days credit -> 0 overdue -> not_due (a bill due TODAY is NOT late)
  { party: P_GANESH, billDate: '2026-06-01', creditDays: 45, amount: '-87500.50', daysSinceBill: 45, expectBucket: 'not_due' },
  // 10 days old, no credit terms -> 10 overdue -> 0_30
  { party: P_CAFE, billDate: '2026-07-06', creditDays: 0, amount: '-2500.25', daysSinceBill: 10, expectBucket: '0_30' },
  // 57 days old, no credit terms -> 57 overdue -> 31_60
  { party: P_ZED, billDate: '2026-05-20', creditDays: 0, amount: '-5000.00', daysSinceBill: 57, expectBucket: '31_60' },
];

/** Payables are Cr -> positive. */
const PAYABLES: BillFixture[] = [
  { party: P_STEEL, billDate: '2026-06-26', creditDays: 30, amount: '64000.00', daysSinceBill: 20, expectBucket: 'not_due' },
  { party: P_TATA, billDate: '2026-04-07', creditDays: 30, amount: '18500.00', daysSinceBill: 100, expectBucket: '61_90' },
];

/** Ledger grain, because the owner wants "HDFC CA 4471", not "Bank Accounts". */
const CASH_BANK = [
  { ledger: 'HDFC CA 4471', parent: 'Bank Accounts', closing: '-342110.75' },
  { ledger: 'Cash-in-Hand', parent: 'Cash-in-Hand', closing: '-48250.00' },
  // An overdraft is a LIABILITY: Cr, positive. It must pull the headline total DOWN.
  { ledger: 'ICICI OD 8890', parent: 'Bank OD A/c', closing: '125000.00' },
];

const STOCK = [
  { group: 'Raw Material', closing: '-220000.00' },
  { group: 'Finished Goods', closing: '-180000.00' },
];

/** Current month P&L. Income Cr positive, expenses Dr negative -> profit is a plain sum. */
const REVENUE = [
  { group: 'Sales Accounts', amount: '500000.00' },
  { group: 'Purchase Accounts', amount: '-300000.00' },
  { group: 'Direct Expenses', amount: '-45000.00' },
  { group: 'Indirect Expenses', amount: '-30000.00' },
];

/** The chart of accounts — the prober's ORACLE. Must corroborate the numbers above. */
const GROUPS = [
  { name: 'Sundry Debtors', parent: 'Current Assets', primary: 'Current Assets', isRevenue: '0', opening: '-180000.00', closing: '-220000.75' },
  { name: 'Sundry Creditors', parent: 'Current Liabilities', primary: 'Current Liabilities', isRevenue: '0', opening: '70000.00', closing: '82500.00' },
  { name: 'Bank Accounts', parent: 'Current Assets', primary: 'Current Assets', isRevenue: '0', opening: '-300000.00', closing: '-342110.75' },
  { name: 'Cash-in-Hand', parent: 'Current Assets', primary: 'Current Assets', isRevenue: '0', opening: '-40000.00', closing: '-48250.00' },
  { name: 'Bank OD A/c', parent: 'Loans (Liability)', primary: 'Loans (Liability)', isRevenue: '0', opening: '100000.00', closing: '125000.00' },
  { name: 'Stock-in-Hand', parent: 'Current Assets', primary: 'Current Assets', isRevenue: '0', opening: '-350000.00', closing: '-400000.00' },
  { name: 'Current Assets', parent: '', primary: 'Current Assets', isRevenue: '0', opening: '-870000.00', closing: '-1010361.50' },
  { name: 'Current Liabilities', parent: '', primary: 'Current Liabilities', isRevenue: '0', opening: '70000.00', closing: '82500.00' },
  { name: 'Sales Accounts', parent: '', primary: 'Sales Accounts', isRevenue: '1', opening: '0.00', closing: '500000.00' },
  { name: 'Purchase Accounts', parent: '', primary: 'Purchase Accounts', isRevenue: '1', opening: '0.00', closing: '-300000.00' },
];

/** The dialect this fake Tally speaks. NOT the documented default — the prober must find it. */
const DIALECT = { collection: 'Bill', party: '$LedgerName' } as const;

// ============================================================ fake Tally

const dec = (s: string) => s; // readability marker for values already decoded

/** Build an XMLTAG response body. Values must already be wire-escaped. */
function envelope(rows: string[][]): string {
  const body = rows
    .map((cols) =>
      cols
        .map((c, i) => {
          const tag = `F${String(i + 1).padStart(2, '0')}`;
          return `<${tag}>${c}</${tag}>`;
        })
        .join(''),
    )
    .join('');
  return `<ENVELOPE>${body}</ENVELOPE>`;
}

/**
 * Decode a request body without assuming its encoding.
 *
 * The transport probes UTF-16LE first (what the one serious production implementation uses) and
 * falls back to UTF-8. A fake that only understood one of them would silently "pass" the
 * encoding negotiation by accident, so it has to handle both — same sniff as the real codec.
 */
function decodeRequest(buf: Buffer): string {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
  const probe = buf.subarray(0, Math.min(512, buf.length));
  let zerosAtOdd = 0;
  for (let i = 1; i < probe.length; i += 2) if (probe[i] === 0) zerosAtOdd++;
  return zerosAtOdd > probe.length / 4 ? buf.toString('utf16le') : buf.toString('utf8');
}

interface TallyStats {
  requests: number;
  byId: Record<string, number>;
  billVariantsTried: string[];
}

function startFakeTally(stats: TallyStats): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = decodeRequest(Buffer.concat(chunks));
      stats.requests++;

      const id = /<ID>(TS\w+)<\/ID>/.exec(body)?.[1] ?? 'unknown';
      stats.byId[id] = (stats.byId[id] ?? 0) + 1;

      // Respond in UTF-16LE with a BOM — the encoding a real Tally is reported to use, and the
      // one that exercises the codec's BOM path rather than the ASCII fallback.
      const send = (xml: string) => {
        res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-16' });
        res.end(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(xml, 'utf16le')]));
      };

      // --- The company probe. Deliberately answers regardless of SVCURRENTCOMPANY.
      if (id === 'TSProbe') {
        send(
          envelope([
            [
              COMPANY.name,
              COMPANY.guid,
              String(COMPANY.altMstId),
              String(COMPANY.altVchId),
              COMPANY.booksFromTally,
              COMPANY.lastVoucher,
              '1',
              COMPANY.state,
            ],
          ]),
        );
        return;
      }

      // --- The oracle: the chart of accounts.
      if (id === 'TSGroups') {
        // If the caller disabled $_PrimaryGroup it sends `<SET>""</SET>` for F03; this Tally
        // supports the method, so the column is populated either way.
        send(
          envelope(
            GROUPS.map((g) => [g.name, g.parent, g.primary, g.isRevenue, g.opening, g.closing, '0']),
          ),
        );
        return;
      }

      // --- Cash and bank at ledger grain.
      if (id === 'TSCashBank') {
        send(envelope(CASH_BANK.map((r) => [r.ledger, r.parent, r.closing])));
        return;
      }

      // --- THE unknown: the outstanding-bills collection.
      if (id === 'TSBills') {
        const askedCollection = /<TYPE>(Bills|Bill)<\/TYPE>/.exec(body)?.[1];
        const askedParty = ['$PartyName', '$LedgerName', '$..Name'].find((m) =>
          body.includes(`<SET>${m}</SET>`),
        );
        stats.billVariantsTried.push(`${askedCollection}+${askedParty}`);

        // Wrong collection type: Tally returns nothing at all.
        if (askedCollection !== DIALECT.collection) {
          send('<ENVELOPE></ENVELOPE>');
          return;
        }

        const payable = body.includes('$$GroupSundryCreditors');
        const bills = payable ? PAYABLES : RECEIVABLES;

        // THE characteristic Tally failure: the RIGHT collection with the WRONG party method
        // returns rows with a SILENTLY EMPTY party column — not an error. The prober must
        // reject this rather than publishing a dashboard of blank debtors.
        const named = askedParty === DIALECT.party;
        send(
          envelope(
            bills.map((b) => [
              named ? b.party.wire : '',
              b.billDate,
              String(b.creditDays),
              b.amount,
              b.isAdvance ? '1' : '0',
              String(b.daysSinceBill),
            ]),
          ),
        );
        return;
      }

      if (id === 'TSStock') {
        send(envelope(STOCK.map((s) => [s.group, s.closing])));
        return;
      }

      if (id === 'TSRevenue') {
        send(envelope(REVENUE.map((r) => [r.group, r.amount])));
        return;
      }

      send('<ENVELOPE></ENVELOPE>');
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

// ============================================================ fake server (REAL handleIngest)

interface StoredSnapshot {
  tenantId: string;
  companyGuid: string;
  section: Section;
  asOf: string;
  contentHash: string;
  envelope: SealedEnvelope;
  snapshotTs: number;
  seq: number;
  deviceId: string;
  bytes: number;
}

interface ServerState {
  snapshots: Map<string, StoredSnapshot>;
  nonces: Set<string>;
  uploads: Array<{ deviceId: string; bytes: number; at: number }>;
  rejections: Array<{ status: number; error: string }>;
}

function startFakeServer(
  state: ServerState,
  auth: { deviceId: string; devicePublicKey: Uint8Array; tenantId: string },
): Promise<http.Server> {
  const key = (t: string, c: string, s: string, a: string) => `${t}|${c}|${s}|${a}`;

  // The REAL ingest handler's dependencies, backed by a Map. Every security check in
  // apps/server/src/ingest.ts — signature, freshness, quota, AAD cross-check — runs for real.
  const deps: IngestDeps = {
    lookupDevice: async (deviceId) =>
      deviceId === auth.deviceId ? { publicKey: auth.devicePublicKey, revoked: false } : undefined,
    // A UNIQUE constraint in production; a Set here. Must report "seen before", not throw.
    rememberNonce: async (deviceId, nonce) => {
      const k = `${deviceId}|${nonce}`;
      if (state.nonces.has(k)) return false;
      state.nonces.add(k);
      return true;
    },
    now: () => Date.now(),
    tenantIdForDevice: async (deviceId) =>
      deviceId === auth.deviceId ? auth.tenantId : undefined,
    latestSnapshot: async (tenantId, companyGuid, section, asOf) => {
      const s = state.snapshots.get(key(tenantId, companyGuid, section, asOf));
      return s ? { snapshotTs: s.snapshotTs, contentHash: s.contentHash } : undefined;
    },
    /**
     * ONE atomic step: record the attempt AND report the resulting count, this one included.
     * In production this is a single `INSERT ... RETURNING` — a read-then-write here would be
     * the exact TOCTOU the real dep's contract forbids.
     */
    reserveUpload: async (deviceId, bytes) => {
      state.uploads.push({ deviceId, bytes, at: Date.now() });
      return state.uploads.filter(
        (u) => u.deviceId === deviceId && u.at > Date.now() - 3_600_000,
      ).length;
    },
    tenantBytesStored: async () =>
      [...state.snapshots.values()].reduce((n, s) => n + s.bytes, 0),
    storeSnapshot: async (row) => {
      // Upsert on (tenant, company, section, as_of) — idempotent by construction.
      state.snapshots.set(key(row.tenantId, row.companyGuid, row.section, row.asOf), row);
    },
    touchDevice: async () => {},
  };

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      void (async () => {
        const raw = new Uint8Array(Buffer.concat(chunks));
        const headers: Record<string, string | undefined> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          headers[k] = Array.isArray(v) ? v[0] : v;
        }
        // The five-line adapter that a Next.js route would be.
        const out = await handleIngest(headers, raw, deps, '127.0.0.1');
        if (out.status !== 200) {
          state.rejections.push({
            status: out.status,
            error: 'error' in out.body ? out.body.error : '?',
          });
        }
        res.writeHead(out.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out.body));
      })();
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server)));
}

// ============================================================ reporting

const failures: string[] = [];
let checks = 0;

function check(name: string, fn: () => void): void {
  checks++;
  try {
    fn();
    console.log(`  ✓ ${name}`);
  } catch (e) {
    const msg = e instanceof Error ? e.message.split('\n')[0] : String(e);
    console.log(`  ✗ ${name}\n      ${msg}`);
    failures.push(`${name}: ${msg}`);
  }
}

function h1(s: string): void {
  console.log(`\n${'='.repeat(74)}\n${s}\n${'='.repeat(74)}`);
}

/** Sum a column of signed decimal strings exactly, via integer paise. */
function sumDecimals(values: readonly string[]): number {
  let paise = 0;
  for (const v of values) {
    const m = /^([+-]?)(\d+)\.(\d{2})$/.exec(v.trim());
    if (!m) throw new Error(`fixture is not a 2dp decimal: ${v}`);
    const n = Number(m[2]! + m[3]!);
    paise += m[1] === '-' ? -n : n;
  }
  return paise / 100;
}

// ============================================================ main

async function main(): Promise<number> {
  h1('TALLY BRIDGE — END-TO-END SIMULATION');
  console.log('Real modules throughout. Fakes ONLY at the two boundaries we cannot have:');
  console.log('  - Tally      : HTTP server speaking the `Bill` + `$LedgerName` dialect');
  console.log('  - Vercel/Neon: HTTP server whose handler IS the real handleIngest\n');

  const tallyStats: TallyStats = { requests: 0, byId: {}, billVariantsTried: [] };
  const serverState: ServerState = {
    snapshots: new Map(),
    nonces: new Set(),
    uploads: [],
    rejections: [],
  };

  // --- Real keys. The identity keypair is the read capability; the device keypair is the
  //     write capability. The Bridge below is handed ONLY the identity PUBLIC key.
  const identity = await generateIdentity();
  const device = await generateDeviceKeypair('device-e2e-001');
  const tenantId = 'tenant-e2e';

  const tally = await startFakeTally(tallyStats);
  const server = await startFakeServer(serverState, {
    deviceId: device.deviceId,
    devicePublicKey: device.publicKey,
    tenantId,
  });
  const tallyPort = (tally.address() as AddressInfo).port;
  const serverPort = (server.address() as AddressInfo).port;
  const dir = mkdtempSync(join(tmpdir(), 'tb-e2e-'));
  const store = new SyncStore(join(dir, 'sync.db'));

  console.log(`fake Tally  : http://127.0.0.1:${tallyPort}`);
  console.log(`fake server : http://127.0.0.1:${serverPort}`);
  console.log(`sync db     : ${join(dir, 'sync.db')}`);

  try {
    // ---------------------------------------------------------------- 1. probe
    h1('1. probeCapabilities — resolving the TDL dialect at runtime');
    const transport = new TallyTransport({ port: tallyPort });
    const quirks = await probeCapabilities(transport, {
      company: COMPANY.name,
      booksFrom: COMPANY.booksFrom,
      asOf: AS_OF,
    });
    console.log(`  tried variants: ${tallyStats.billVariantsTried.join(', ')}`);
    if (VERBOSE) console.log(`  quirks: ${JSON.stringify(quirks, null, 2)}`);

    check('encoding negotiated (UTF-16LE, as the production implementation uses)', () =>
      assert.equal(quirks.requestEncoding, 'utf16le'),
    );
    check('prober converged on the dialect nobody predicted (Bill)', () =>
      assert.equal(quirks.billsCollectionType, DIALECT.collection),
    );
    check('prober converged on the party method ($LedgerName)', () =>
      assert.equal(quirks.billPartyMethod, DIALECT.party),
    );
    check('prober REJECTED the variants that returned blank party names', () =>
      assert.ok(
        tallyStats.billVariantsTried.length > 1,
        'prober accepted the first variant without cross-checking',
      ),
    );
    check('$_PrimaryGroup detected as supported', () =>
      assert.equal(quirks.supportsPrimaryGroupMethod, true),
    );

    // ---------------------------------------------------------------- 2. cycle
    h1('2. buildCycle — extract, gate, seal, sign, upload');
    const events: SyncEvent[] = [];
    const seq = new SeqCounter();
    const cycle = buildCycle({
      transport,
      store,
      // THE security property, visible in the call site: a PUBLIC key and nothing else.
      identityPublicKey: identity.publicKey,
      deviceSecretKey: device.secretKey,
      deviceId: device.deviceId,
      tenantId,
      serverUrl: `http://127.0.0.1:${serverPort}`,
      seq,
      today: () => AS_OF,
      log: (e) => events.push(e),
    });

    await cycle();

    const uploaded = events.filter((e) => e.kind === 'uploaded').length;
    const enqueued = events.filter((e) => e.kind === 'section_enqueued').length;
    if (VERBOSE) for (const e of events) console.log(`  ${JSON.stringify(e)}`);
    console.log(`  Tally requests: ${tallyStats.requests} ${JSON.stringify(tallyStats.byId)}`);
    console.log(`  enqueued=${enqueued} uploaded=${uploaded} stored=${serverState.snapshots.size}`);
    if (serverState.rejections.length > 0) {
      console.log(`  server rejections: ${JSON.stringify(serverState.rejections)}`);
    }

    check('every section was accepted by the real ingest handler (no 4xx)', () =>
      assert.deepEqual(serverState.rejections, []),
    );
    check('all 7 sections reached the server', () =>
      assert.equal(serverState.snapshots.size, 7),
    );
    check('the outbox drained completely', () => assert.equal(store.depth(), 0));

    // ---------------------------------------------------------------- 3. server holds ciphertext
    h1('3. What the server actually holds');
    const anySnap = [...serverState.snapshots.values()][0]!;
    check('the server stores an opaque blob, not the numbers', () => {
      const blob = JSON.stringify(anySnap.envelope);
      for (const secret of ['342110', 'Ganesh', 'A & B Traders', '125000']) {
        assert.ok(!blob.includes(secret), `plaintext "${secret}" LEAKED into the stored envelope`);
      }
    });
    check('the AAD binds tenant, device, company, section and date', () => {
      assert.equal(anySnap.envelope.aad.tenantId, tenantId);
      assert.equal(anySnap.envelope.aad.deviceId, device.deviceId);
      assert.equal(anySnap.envelope.aad.companyGuid, COMPANY.guid);
      assert.equal(anySnap.envelope.aad.asOf, AS_OF);
    });

    // ---------------------------------------------------------------- 4. decrypt at the far end
    h1('4. openSection — decrypting with the identity SECRET key');
    const opened = new Map<Section, any>();
    for (const snap of serverState.snapshots.values()) {
      const plain = await openSection(snap.envelope, {
        identityPublicKey: identity.publicKey,
        identitySecretKey: identity.secretKey,
        // The slot the reader ASKED FOR. Without this, the server could answer a request for
        // one company with another company's authentic envelope.
        expect: {
          tenantId,
          companyGuid: snap.companyGuid,
          section: snap.section,
          asOf: snap.asOf,
        },
        // PINNED, and note where it comes from: the `device` object this script generated
        // locally — NOT from `serverState`. That distinction is the entire security property.
        // Had the reader asked the server for the device's public key, the server would simply
        // have answered with a key it made up and signed its forgeries with the matching
        // secret. See packages/crypto/src/trust.ts.
        trustedDevices: [{ deviceId: device.deviceId, publicKey: device.publicKey }],
      });
      opened.set(snap.section, plain);
    }
    console.log(`  decrypted ${opened.size} sections: ${[...opened.keys()].join(', ')}`);

    // ---------------------------------------------------------------- 5. THE agreement
    h1('5. THE ASSERTION — do the far-end numbers equal what Tally served?');

    const company = opened.get('company');
    check('company: GUID is the identity, and it survived', () =>
      assert.equal(company.rows[0].companyGuid, COMPANY.guid),
    );
    check('company: name survived', () => assert.equal(company.rows[0].name, COMPANY.name));

    const cash = opened.get('cash_bank');
    check('cash_bank: every ledger arrived, with its exact closing balance', () => {
      assert.equal(cash.rows.length, CASH_BANK.length);
      for (const want of CASH_BANK) {
        const got = cash.rows.find((r: any) => r.ledgerName === want.ledger);
        assert.ok(got, `ledger ${want.ledger} never arrived`);
        assert.equal(String(got.closing), want.closing, `closing for ${want.ledger}`);
      }
    });

    const recv = opened.get('ageing_receivable');
    check('ageing_receivable: the tricky party names survived the whole pipeline', () => {
      const names = new Set(recv.rows.map((r: any) => r.partyName));
      for (const p of [P_AB, P_GANESH, P_CAFE, P_ZED]) {
        assert.ok(names.has(p.name), `party "${p.name}" did not survive (got: ${[...names].join(' | ')})`);
      }
    });
    check('ageing_receivable: every bill landed in the right bucket', () => {
      for (const b of RECEIVABLES) {
        const row = recv.rows.find((r: any) => r.partyName === b.party.name);
        assert.ok(row, `no row for ${b.party.name}`);
        assert.equal(row.bucket, b.expectBucket, `bucket for ${b.party.name}`);
      }
    });
    check('ageing_receivable: totals equal the sum of what Tally served', () => {
      const want = sumDecimals(RECEIVABLES.map((b) => b.amount));
      const got = sumDecimals(recv.totals.map((t: any) => String(t.amount)));
      assert.equal(got, want);
    });
    check('ageing_receivable: totals[] agrees with the rows[] matrix (nothing lost)', () => {
      const fromTotals = sumDecimals(recv.totals.map((t: any) => String(t.amount)));
      const fromRows = sumDecimals(recv.rows.map((r: any) => String(r.amount)));
      assert.equal(fromTotals, fromRows);
    });
    check('ageing_receivable: the Sundry Debtors group corroborates the bills', () => {
      // The oracle and the bills are two independent paths to the same number. If they
      // disagree, one of them is lying and the dashboard cannot be trusted.
      const debtors = GROUPS.find((g) => g.name === 'Sundry Debtors')!;
      assert.equal(sumDecimals(RECEIVABLES.map((b) => b.amount)), sumDecimals([debtors.closing]));
    });

    const pay = opened.get('ageing_payable');
    check('ageing_payable: totals equal the sum of what Tally served', () => {
      const want = sumDecimals(PAYABLES.map((b) => b.amount));
      const got = sumDecimals(pay.totals.map((t: any) => String(t.amount)));
      assert.equal(got, want);
    });

    const stock = opened.get('stock_value');
    check('stock_value: total equals what Tally served', () => {
      const want = sumDecimals(STOCK.map((s) => s.closing));
      const got = sumDecimals(stock.rows.map((r: any) => String(r.closingValue)));
      assert.equal(got, want);
    });

    const rev = opened.get('period_revenue');
    check('period_revenue: every group arrived with its exact amount', () => {
      for (const want of REVENUE) {
        const got = rev.rows.find((r: any) => r.groupName === want.group);
        assert.ok(got, `revenue group ${want.group} never arrived`);
        assert.equal(String(got.amount), want.amount);
      }
    });

    const groups = opened.get('group_balance');
    check('group_balance: the chart of accounts arrived intact', () =>
      assert.equal(groups.rows.length, GROUPS.length),
    );

    // The paisa. -87500.50 and -2500.25 exist purely so that a float anywhere on the path
    // shows up here as a rounding error rather than passing unnoticed.
    check('THE PAISA: no float crept into the money path', () => {
      const want = sumDecimals(RECEIVABLES.map((b) => b.amount)); // -220000.75
      const got = sumDecimals(recv.totals.map((t: any) => String(t.amount)));
      assert.equal(got, want);
      assert.equal(got, -220000.75);
    });

    // ---------------------------------------------------------------- 6. idempotency / gates
    h1('6. Running the cycle again — the gates must hold');
    const events2: SyncEvent[] = [];
    const cycle2 = buildCycle({
      transport,
      store,
      identityPublicKey: identity.publicKey,
      deviceSecretKey: device.secretKey,
      deviceId: device.deviceId,
      tenantId,
      serverUrl: `http://127.0.0.1:${serverPort}`,
      seq,
      today: () => AS_OF,
      log: (e) => events2.push(e),
    });
    await cycle2();
    const gate = events2.find((e) => e.kind === 'gate');
    const uploaded2 = events2.filter((e) => e.kind === 'uploaded').length;
    console.log(`  gate decision: ${gate && 'decision' in gate ? gate.decision.action : '?'}`);
    console.log(`  uploads on the second cycle: ${uploaded2}`);
    check('the AlterID gate skipped an unchanged company (no re-upload)', () => {
      assert.equal(uploaded2, 0, 'unchanged data was uploaded again — the gate is not holding');
    });

    // ---------------------------------------------------------------- 7. the cards
    h1('7. The card layer — what a human would actually see');
    console.log('Feeding the DECRYPTED rows straight into packages/viewmodel, exactly as a');
    console.log('dashboard would.\n');

    const cardErrors: string[] = [];
    const tryCard = (name: string, fn: () => void) => {
      try {
        fn();
      } catch (e) {
        const m = e instanceof Error ? e.message : String(e);
        cardErrors.push(`${name}: ${m}`);
        console.log(`  !! ${name} THREW: ${m}`);
      }
    };

    tryCard('cashBankCard', () => {
      const c = cashBankCard(cash.rows);
      console.log(`  Cash & Bank      ${c.total.display}  (${c.total.compact})  tone=${c.tone}`);
      for (const a of c.accounts) console.log(`      ${a.name.padEnd(18)} ${a.balance.display}`);
    });
    tryCard('ageingCard(receivable)', () => {
      const c = ageingCard(recv.totals, recv.rows, 'receivable');
      console.log(`\n  Receivables      ${c.total.display}   overdue ${c.overdue.display}  tone=${c.tone}`);
      for (const p of c.topParties) console.log(`      ${p.name.padEnd(24)} ${p.amount.display}`);
    });
    tryCard('ageingCard(payable)', () => {
      const c = ageingCard(pay.totals, pay.rows, 'payable');
      console.log(`\n  Payables         ${c.total.display}   overdue ${c.overdue.display}`);
    });
    tryCard('stockCard', () => {
      const c = stockCard(stock.rows);
      console.log(`\n  Stock            ${c.total.display}`);
    });
    tryCard('profitCard', () => {
      const c = profitCard(rev.rows, []);
      console.log(`\n  Profit           ${c.current.display}`);
    });
    tryCard('salesTrendCard', () => {
      const c = salesTrendCard(rev.rows);
      console.log(`\n  Sales trend      ${c.points.map((p) => `${p.label}=${p.value.display}`).join(' ')}`);
    });
    tryCard('balanceSheetTree', () => {
      const t = balanceSheetTree(groups.rows);
      console.log(`\n  Balance sheet    ${t.map((n) => `${n.name}=${n.amount.display}`).join('  ')}`);
    });

    // ---------------------------------------------------------------- 8. the verdict on the cards
    h1('8. Does the CARD layer agree with Tally?');

    check('THE MONEY SIGN: a bank balance must never display negative', () => {
      const c = cashBankCard(cash.rows);
      const hdfc = c.accounts.find((a) => a.name === 'HDFC CA 4471')!;
      assert.ok(
        !hdfc.balance.display.startsWith('-'),
        `a funded bank account displayed as ${hdfc.balance.display} — the Dr/Cr flip is broken`,
      );
      assert.equal(hdfc.balance.raw, 342110.75);
    });

    check('cash & bank total nets the overdraft correctly', () => {
      // 342110.75 + 48250.00 - 125000.00 = 265360.75
      const want = -sumDecimals(CASH_BANK.map((r) => r.closing));
      const c = cashBankCard(cash.rows);
      assert.equal(c.total.raw, want);
      assert.equal(c.total.raw, 265360.75);
    });

    check('receivables card total equals what Tally served (sign flipped)', () => {
      const want = -sumDecimals(RECEIVABLES.map((b) => b.amount));
      const c = ageingCard(recv.totals, recv.rows, 'receivable');
      assert.equal(c.total.raw, want);
      assert.equal(c.total.raw, 220000.75);
    });

    check('Indian digit grouping (lakh/crore, not thousands)', () => {
      assert.equal(formatMoney(220000.75), '₹2,20,001');
      assert.equal(formatMoney(12345678), '₹1,23,45,678');
    });

    check('profitCard survives the real wire format', () => {
      const c = profitCard(rev.rows, []);
      assert.equal(c.current.raw, 125000);
    });

    check('salesTrendCard survives the real wire format', () => {
      const c = salesTrendCard(rev.rows);
      assert.equal(c.points[0]!.value.raw, 500000);
    });

    check('balanceSheetTree survives the real wire format', () => {
      const t = balanceSheetTree(groups.rows);
      const node = t.find((n) => n.name === 'Current Assets');
      assert.ok(node, 'Current Assets missing from the tree');
      assert.ok(
        node.amount.display !== '₹—',
        `the balance sheet rendered "₹—" instead of a number`,
      );
    });

    if (cardErrors.length > 0) {
      for (const e of cardErrors) failures.push(`card threw — ${e}`);
    }
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    await new Promise<void>((r) => tally.close(() => r()));
    await new Promise<void>((r) => server.close(() => r()));
  }

  // ---------------------------------------------------------------- verdict
  h1('VERDICT');
  console.log(`${checks - failures.length}/${checks} checks passed\n`);

  if (failures.length === 0) {
    console.log('THE PIPELINE AGREES END TO END.');
    console.log('The numbers Tally served are the numbers that came out of the far end, and');
    console.log('the server never held a key that could read them.');
    return 0;
  }

  console.log('*** THE PIPELINE DOES NOT AGREE END TO END. ***\n');
  for (const f of failures) console.log(`  - ${f}`);
  console.log(
    '\nThis is not a test-harness problem. Every module passes its own unit tests; they',
  );
  console.log('disagree with EACH OTHER about the shape of the data on the wire. See');
  console.log('scripts/smoke-launch.md ("BUG-1: the wire carries strings, the cards expect');
  console.log('numbers") for the diagnosis and the fix.');
  return 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error('\n*** THE SIMULATION ITSELF FAILED TO RUN ***\n');
    console.error(e);
    process.exit(2);
  },
);
