import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { generateIdentity, openSection } from '@tally-bridge/crypto';
import { generateDeviceKeypair } from '@tally-bridge/protocol';
import { SyncStore, type UploadResult } from '@tally-bridge/sync';
import { QUIRKS_SCHEMA_VERSION, TallyTransport, type TallyQuirks } from '@tally-bridge/tally';
import type { SealedEnvelope } from '@tally-bridge/core';
import { buildCycle, createUploader } from '../src/main/cycle.ts';

/**
 * These tests exist because every individual piece below them already passes.
 *
 * The transport, the gates, the prober, the ageing aggregation and the crypto are each covered
 * in their own package. What has never been exercised until this file is the WIRING — and the
 * wiring is exactly where the conventions get violated quietly: a name used where a GUID
 * belongs, a paisa lost to a float, a blank party column shipped as a dashboard. So the fake
 * Tally below is a real HTTP server speaking real (malformed-ish) Tally XML, and the assertions
 * are made on the bytes that would actually leave the machine.
 */

// ---------------------------------------------------------------- fake Tally

interface FakeTallyConfig {
  /** Party name column of the bills response. Set '' to simulate THE characteristic failure. */
  partyNames?: [string, string];
  /** Sundry Debtors closing balance — the oracle the prober checks silence against. */
  debtorsBalance?: string;
  /** Bills rows, as Tally would emit them: [party, billDate, creditDays, amount, isAdv, days]. */
  bills?: string[][];
  cashBankAmount?: string;
  /**
   * What the StockGroup collection's `$ClosingValue` idiom emits — THE doubtful sign. The
   * default matches the (verified) group idiom; set a positive value to model the Tally where
   * `$$IsDebit` does not fire for StockGroup and the extraction must negate.
   */
  stockValue?: string;
  /** Stock-in-Hand's closing in the chart of accounts — the probe's trusted reference. */
  stockInHandBalance?: string;
}

interface FakeTally {
  port: number;
  /** Every request body, so we can prove what we did and did not ask Tally for. */
  requests: string[];
  countOf: (id: string) => number;
  close: () => Promise<void>;
}

async function startFakeTally(cfg: FakeTallyConfig = {}): Promise<FakeTally> {
  const requests: string[] = [];
  const parties = cfg.partyNames ?? ['A &amp; B Traders', 'Zed Enterprises'];

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      // The transport probes UTF-16LE first; decode both so the fake answers either.
      const raw = Buffer.concat(chunks);
      const body = raw.includes(0) ? raw.toString('utf16le') : raw.toString('utf8');
      requests.push(body);

      const send = (xml: string) => {
        res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-8' });
        res.end(xml);
      };

      if (body.includes('<ID>TSProbe</ID>')) {
        send(
          '<ENVELOPE><F01>Acme Traders</F01><F02>guid-acme</F02><F03>1200</F03><F04>3400</F04>' +
            '<F05>20260401</F05><F06>20260716</F06><F07>1</F07><F08>Maharashtra</F08></ENVELOPE>',
        );
        return;
      }

      if (body.includes('<ID>TSGroups</ID>')) {
        send(
          '<ENVELOPE>' +
            `<F01>Sundry Debtors</F01><F02>Current Assets</F02><F03>Current Assets</F03><F04>0</F04><F05>0.00</F05><F06>${cfg.debtorsBalance ?? '-130000.00'}</F06><F07>0</F07>` +
            '<F01>Bank Accounts</F01><F02>Current Assets</F02><F03>Current Assets</F03><F04>0</F04><F05>0.00</F05><F06>-342110.75</F06><F07>0</F07>' +
            `<F01>Stock-in-Hand</F01><F02>Current Assets</F02><F03>Current Assets</F03><F04>0</F04><F05>0.00</F05><F06>${cfg.stockInHandBalance ?? '-88000.25'}</F06><F07>0</F07>` +
            '<F01>Sales Accounts</F01><F02></F02><F03>Sales Accounts</F03><F04>1</F04><F05>0.00</F05><F06>500000.00</F06><F07>0</F07>' +
            '</ENVELOPE>',
        );
        return;
      }

      if (body.includes('<ID>TSCashBank</ID>')) {
        send(
          '<ENVELOPE><F01>HDFC CA 4471</F01><F02>Bank Accounts</F02>' +
            `<F03>${cfg.cashBankAmount ?? '-342110.75'}</F03></ENVELOPE>`,
        );
        return;
      }

      if (body.includes('<ID>TSBills</ID>')) {
        const payable = body.includes('$$GroupSundryCreditors');
        const rows = cfg.bills ?? [
          [parties[0]!, '2026-01-01', '30', '-125000.00', '0', '90'],
          [parties[1]!, '2026-02-01', '0', '-5000.50', '0', '10'],
        ];
        send(
          '<ENVELOPE>' +
            rows
              .map((r) =>
                r
                  .map((v, i) => `<F0${i + 1}>${payable && i === 3 ? flipSign(v) : v}</F0${i + 1}>`)
                  .join(''),
              )
              .join('') +
            '</ENVELOPE>',
        );
        return;
      }

      if (body.includes('<ID>TSStock</ID>')) {
        send(`<ENVELOPE><F01>Hardware</F01><F02>${cfg.stockValue ?? '-88000.25'}</F02></ENVELOPE>`);
        return;
      }

      if (body.includes('<ID>TSRevenue</ID>')) {
        send(
          '<ENVELOPE><F01>Sales Accounts</F01><F02>500000.00</F02>' +
            '<F01>Direct Expenses</F01><F02>-120000.00</F02></ENVELOPE>',
        );
        return;
      }

      send('<ENVELOPE></ENVELOPE>');
    });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;

  return {
    port,
    requests,
    countOf: (id) => requests.filter((b) => b.includes(`<ID>${id}</ID>`)).length,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

function flipSign(v: string): string {
  return v.startsWith('-') ? v.slice(1) : `-${v}`;
}

// ---------------------------------------------------------------- harness

interface Harness {
  cycle: () => Promise<void>;
  store: SyncStore;
  uploads: Array<{ envelopeJson: string; key: string }>;
  setUploadResult: (r: UploadResult) => void;
  identity: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** The Bridge's Ed25519 device key. `open()` pins it as the roster — see the note there. */
  device: { publicKey: Uint8Array };
  advance: (ms: number) => void;
  cleanup: () => void;
}

async function harness(opts: { port: number; store?: SyncStore }): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), 'tally-cycle-'));
  const store = opts.store ?? new SyncStore(join(dir, 'sync.db'));
  const identity = await generateIdentity();
  const device = await generateDeviceKeypair('dev_1');
  const uploads: Array<{ envelopeJson: string; key: string }> = [];
  let uploadResult: UploadResult = { ok: true, retryable: false };
  let clock = Date.parse('2026-07-16T10:00:00Z');

  const cycle = buildCycle({
    transport: new TallyTransport({ port: opts.port }),
    store,
    identityPublicKey: identity.publicKey,
    deviceSecretKey: device.secretKey,
    deviceId: 'dev_1',
    tenantId: 'tnt_1',
    serverUrl: 'https://acme.example',
    now: () => clock,
    today: () => '2026-07-16',
    upload: async (envelopeJson, key) => {
      uploads.push({ envelopeJson, key });
      return uploadResult;
    },
  });

  return {
    cycle,
    store,
    uploads,
    identity,
    device: { publicKey: device.publicKey },
    setUploadResult: (r) => {
      uploadResult = r;
    },
    advance: (ms) => {
      clock += ms;
    },
    cleanup: () => {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Decrypt an upload. Only the identity SECRET key can do this — the Bridge never holds it.
 *
 * Two deliberately weak arguments here, called out so nobody later mistakes them for coverage:
 *
 *   - `trustedDevices` pins the harness's own device key. That is legitimate (a pinned roster is
 *     exactly the real contract) but it proves nothing about where a real reader GETS that key,
 *     which is the open question in the design. `packages/crypto` tests the refusals.
 *   - `expect` is the envelope's own AAD, so the slot check here is tautological. It cannot be
 *     otherwise: this helper reads back an upload the test just produced, so there is no
 *     independent "what was asked for" to compare against. AAD binding is tested where a
 *     mismatch can actually be constructed — in crypto, not here.
 *
 * What this helper IS for: getting at the plaintext so the tests below can assert on the money.
 */
async function open(h: Harness, section: string): Promise<Record<string, unknown>> {
  const up = h.uploads.find((u) => (JSON.parse(u.envelopeJson) as SealedEnvelope).aad.section === section);
  assert.ok(up, `no upload for section ${section}`);
  const env = JSON.parse(up.envelopeJson) as SealedEnvelope;
  return (await openSection(env, {
    identityPublicKey: h.identity.publicKey,
    identitySecretKey: h.identity.secretKey,
    expect: env.aad,
    trustedDevices: [{ deviceId: env.aad.deviceId, publicKey: h.device.publicKey }],
  })) as Record<string, unknown>;
}

const GOOD_QUIRKS: TallyQuirks = {
  flavour: 'prime',
  tallyVersion: 'unknown',
  requestEncoding: 'utf8',
  supportsPrimaryGroupMethod: true,
  useGroupBankFunctions: true,
  billsCollectionType: 'Bills',
  billPartyMethod: '$PartyName',
  // 'ok' = the probe checked this book's Dr/Cr signs and they came out the way the TDL idiom
  // assumes. These fixtures serve amounts already in that convention, so 'ok' is the honest
  // value; 'unknown' would be claiming the canary never ran on a book where it plainly would.
  amountSigns: 'ok',
  // 'dr_negative' for the same reason amountSigns is 'ok': these fixtures serve stock values
  // already in the Dr-negative convention, so this is what the probe would measure here.
  stockValueSign: 'dr_negative',
  notes: [],
};

// ---------------------------------------------------------------- the happy path

test('END TO END: probes, extracts every section, seals, and uploads', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();

    const sections = h.uploads
      .map((u) => (JSON.parse(u.envelopeJson) as SealedEnvelope).aad.section)
      .sort();
    assert.deepEqual(sections, [
      'ageing_payable',
      'ageing_receivable',
      'cash_bank',
      'company',
      'group_balance',
      'period_revenue',
      'stock_value',
    ]);
    assert.equal(h.store.depth(), 0, 'a successful upload clears the outbox');

    // The company is keyed by GUID everywhere, never by name.
    for (const u of h.uploads) {
      assert.equal((JSON.parse(u.envelopeJson) as SealedEnvelope).aad.companyGuid, 'guid-acme');
      assert.match(u.key, /^guid-acme\|/);
    }

    // Nothing readable left the machine.
    assert.ok(!h.uploads.some((u) => u.envelopeJson.includes('HDFC')));
    assert.ok(!h.uploads.some((u) => u.envelopeJson.includes('342110.75')));
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('the company section carries the GUID as identity and the name as mere data', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const payload = await open(h, 'company');
    assert.deepEqual(payload, {
      section: 'company',
      rows: [
        {
          companyGuid: 'guid-acme',
          name: 'Acme Traders',
          state: 'Maharashtra',
          booksFrom: '2026-04-01',
          lastVoucherDate: '2026-07-16',
          tallyFlavour: 'prime',
          tallyVersion: 'unknown',
        },
      ],
    });
  } finally {
    h.cleanup();
    await tally.close();
  }
});

// ---------------------------------------------------------------- money

test('AMOUNTS SURVIVE EXACTLY, and Dr stays negative', async () => {
  // The whole money path in one assertion: Tally's decimal string -> integer paise -> canonical
  // wire string, with no float anywhere in between to lose a paisa.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();

    const cash = await open(h, 'cash_bank');
    assert.deepEqual(cash, {
      section: 'cash_bank',
      rows: [
        {
          companyGuid: 'guid-acme',
          asOf: '2026-07-16',
          ledgerName: 'HDFC CA 4471',
          parent: 'Bank Accounts',
          // Dr negative: a bank balance is an asset, so it arrives NEGATIVE and the card layer
          // flips it for display. If this ever reads positive, cashBankCard shows a debt.
          closing: '-342110.75',
        },
      ],
    });

    const stock = await open(h, 'stock_value');
    assert.equal((stock.rows as Array<{ closingValue: string }>)[0]!.closingValue, '-88000.25');

    const groups = await open(h, 'group_balance');
    const sales = (groups.rows as Array<{ groupName: string; closing: string; isRevenue: boolean }>).find(
      (r) => r.groupName === 'Sales Accounts',
    );
    assert.equal(sales!.closing, '500000.00', 'Cr positive');
    assert.equal(sales!.isRevenue, true);
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('a half-paisa amount is not rounded away', async () => {
  // `Number("5000.50") * 100` is 500049.99999999994 in float64. Routing money through a float
  // and rounding loses a paisa here, silently and forever.
  const tally = await startFakeTally({
    bills: [['Half Paisa Co', '2026-01-01', '0', '-5000.50', '0', '5']],
  });
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const ageing = await open(h, 'ageing_receivable');
    const totals = ageing.totals as Array<{ amount: string; billCount: number }>;
    assert.equal(totals[0]!.amount, '-5000.50');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('ageing buckets by days OVERDUE and totals cover every bill', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const ageing = await open(h, 'ageing_receivable');
    const rows = ageing.rows as Array<{ partyName: string; bucket: string; amount: string }>;

    // 90 days old, 30 days credit => 60 days overdue => '31_60'. Bucketing on days SINCE the
    // bill would have said '61_90' and told the owner their customer is later than they are.
    const ab = rows.find((r) => r.partyName === 'A & B Traders');
    assert.equal(ab!.bucket, '31_60');
    assert.equal(ab!.amount, '-125000.00');

    // 10 days old, no credit period => 10 days overdue.
    assert.equal(rows.find((r) => r.partyName === 'Zed Enterprises')!.bucket, '0_30');

    const totals = ageing.totals as Array<{ amount: string; billCount: number }>;
    const totalPaise = totals.reduce((n, t) => n + Math.round(Number(t.amount) * 100), 0);
    assert.equal(totalPaise, -13_000_050);
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('payables are the same path with the other sign', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const payable = await open(h, 'ageing_payable');
    const rows = payable.rows as Array<{ side: string; amount: string }>;
    assert.ok(rows.every((r) => r.side === 'payable'));
    assert.ok(rows.some((r) => r.amount === '125000.00'), 'Cr positive');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

// ---------------------------------------------------------------- Tally closed

test('TALLY CLOSED IS A SILENT NO-OP, not an error', async () => {
  // The normal state every night and every weekend. Throwing here would light up an error the
  // owner sees more often than not, and they would learn to ignore it.
  const dead = await startFakeTally();
  const port = dead.port;
  await dead.close(); // nothing is listening now => ECONNREFUSED

  const h = await harness({ port });
  try {
    await h.cycle(); // must not throw
    assert.equal(h.uploads.length, 0);
    assert.equal(h.store.getWatermark('guid-acme'), undefined);
  } finally {
    h.cleanup();
  }
});

test('Tally closed still drains the outbox', async () => {
  // Uploads have nothing to do with Tally being up. A laptop that reconnects at 2am must flush.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    h.setUploadResult({ ok: false, retryable: true });
    await h.cycle();
    assert.ok(h.store.depth() > 0);

    await tally.close(); // Tally shuts
    h.setUploadResult({ ok: true, retryable: false });
    h.advance(3 * 60 * 60 * 1000); // past the backoff

    const before = h.uploads.length;
    await h.cycle();
    assert.ok(h.uploads.length > before, 'the queued sections must still upload');
    assert.equal(h.store.depth(), 0);
  } finally {
    h.cleanup();
  }
});

test('a Tally FAULT is surfaced, unlike Tally merely being shut', async () => {
  // Tally reports errors inside a 200 OK body. A licence problem or bad TDL is a real failure
  // and must reach the owner rather than being filed under "probably the weekend".
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-8' });
    res.end('<ENVELOPE><LINEERROR>Could not set SVCURRENTCOMPANY</LINEERROR></ENVELOPE>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  const h = await harness({ port });
  try {
    await assert.rejects(() => h.cycle(), /Tally reported a problem/);
  } finally {
    h.cleanup();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

// ---------------------------------------------------------------- quirks cache

test('QUIRKS ARE CACHED: the ~8-round-trip probe does not run every cycle', async () => {
  // Tally is a single-threaded desktop app the owner is typing into. Re-probing it every
  // fifteen minutes for an answer we already have is exactly the disrespect to avoid.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const probedAt = h.store.getQuirks()?.probedAt;
    assert.ok(probedAt, 'the first cycle must probe and cache');

    // Probe + extract both hit these on cycle 1.
    const cashBankAfterFirst = tally.countOf('TSCashBank');
    assert.equal(cashBankAfterFirst, 2, 'one for the capability probe, one for the section');

    // Force a full re-extract without a Tally restart: watermarks move.
    h.store.setWatermark({ companyGuid: 'guid-acme', altMstId: 1, altVchId: 1 }, Date.now());
    h.advance(60_000);
    await h.cycle();

    assert.equal(h.store.getQuirks()?.probedAt, probedAt, 'must not re-probe');
    assert.equal(
      tally.countOf('TSCashBank'),
      cashBankAfterFirst + 1,
      'the second cycle asks once, for the section only',
    );
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('the cache ages out after 30 days rather than lasting forever', async () => {
  // Tally upgrades in place and its version string is not reliable, so a cache that never
  // expires is how a product ships a wrong answer forever.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const probedAt = h.store.getQuirks()!.probedAt;

    h.advance(31 * 24 * 3600 * 1000);
    h.store.setWatermark({ companyGuid: 'guid-acme', altMstId: 1, altVchId: 1 }, Date.now());
    await h.cycle();

    assert.notEqual(h.store.getQuirks()!.probedAt, probedAt, 'must re-probe after 30 days');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('a cached quirks row from an older schema is not trusted', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    h.store.setQuirks({
      quirksSchemaVersion: QUIRKS_SCHEMA_VERSION - 1,
      tallyVersion: 'unknown',
      probedAt: Date.parse('2026-07-16T09:59:00Z'),
      json: JSON.stringify({ ...GOOD_QUIRKS, billPartyMethod: '$..Name' }),
    });
    await h.cycle();
    assert.equal(h.store.getQuirks()!.quirksSchemaVersion, QUIRKS_SCHEMA_VERSION);
    const cached = JSON.parse(h.store.getQuirks()!.json) as TallyQuirks;
    assert.equal(cached.billPartyMethod, '$PartyName', 're-probed rather than trusting the row');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('the cached quirks actually drive the requests', async () => {
  // A cache that is read but not honoured is worse than no cache: it would look correct while
  // sending whatever the defaults happen to be.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    h.store.setQuirks({
      quirksSchemaVersion: QUIRKS_SCHEMA_VERSION,
      tallyVersion: 'unknown',
      probedAt: Date.parse('2026-07-16T09:59:00Z'),
      json: JSON.stringify({
        ...GOOD_QUIRKS,
        supportsPrimaryGroupMethod: false,
        useGroupBankFunctions: false,
        billsCollectionType: 'Bill',
        billPartyMethod: '$LedgerName',
      }),
    });
    await h.cycle();

    const bills = tally.requests.filter((b) => b.includes('<ID>TSBills</ID>'));
    assert.equal(bills.length, 2, 'receivable + payable, and no probing');
    assert.ok(bills.every((b) => b.includes('<TYPE>Bill</TYPE>')));
    assert.ok(bills.every((b) => b.includes('<SET>$LedgerName</SET>')));

    const cashBank = tally.requests.find((b) => b.includes('<ID>TSCashBank</ID>'))!;
    assert.ok(!cashBank.includes('$$GroupBank'), 'must use the _PrimaryGroup fallback');

    const groups = tally.requests.find((b) => b.includes('<ID>TSGroups</ID>'))!;
    assert.ok(!groups.includes('$_PrimaryGroup'));
  } finally {
    h.cleanup();
    await tally.close();
  }
});

// ---------------------------------------------------------------- the stock sign

test('THE STOCK SIGN IS MEASURED, AND THE MEASUREMENT DRIVES THE EXTRACTION', async () => {
  // This Tally's `$$IsDebit` does not fire for StockGroup: the idiom emits +88000.25 while the
  // books' Stock-in-Hand says the same stock is Dr (negative). Unprobed, the wire would carry
  // +88000.25, stockCard would flip it, and the owner would read stock of MINUS ₹88,000.25.
  // The probe must measure the inversion and the extraction must negate — so the bytes that
  // leave the machine are already in the house convention.
  const tally = await startFakeTally({ stockValue: '88000.25' });
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();

    const quirks = JSON.parse(h.store.getQuirks()!.json) as TallyQuirks;
    assert.equal(quirks.stockValueSign, 'positive_magnitude');

    const stock = await open(h, 'stock_value');
    assert.equal(
      (stock.rows as Array<{ closingValue: string }>)[0]!.closingValue,
      '-88000.25',
      'the extraction must negate what the probe measured as a positive magnitude',
    );
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('the default fixture measures dr_negative and passes stock through untouched', async () => {
  // The mirror of the test above, so the negation cannot be "fixed" by negating always.
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const quirks = JSON.parse(h.store.getQuirks()!.json) as TallyQuirks;
    assert.equal(quirks.stockValueSign, 'dr_negative');
    const stock = await open(h, 'stock_value');
    assert.equal((stock.rows as Array<{ closingValue: string }>)[0]!.closingValue, '-88000.25');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('an unverifiable stock sign is recorded as unknown and does NOT correct anything', async () => {
  // Stock-in-Hand is zero (a non-integrated book), so there is no trusted reference. One
  // unverifiable signal must not flip an extraction: the documented Dr-negative idiom stays
  // ASSUMED, uncorrected, and the quirk says so — this is the deliberate residual, chosen over
  // refusing to sync a whole company for one card, and over an empty section that would
  // publish "stock: 0" to a business holding stock.
  const tally = await startFakeTally({ stockInHandBalance: '0.00', stockValue: '88000.25' });
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const quirks = JSON.parse(h.store.getQuirks()!.json) as TallyQuirks;
    assert.equal(quirks.stockValueSign, 'unknown');
    const stock = await open(h, 'stock_value');
    assert.equal(
      (stock.rows as Array<{ closingValue: string }>)[0]!.closingValue,
      '88000.25',
      'an unmeasured correction must never be applied on a hunch',
    );
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('an unresolved stock sign re-probes daily instead of waiting 30 days', async () => {
  // "Re-probe when inventory appears", bounded at a day of staleness: the first stocked month
  // must not render under an unverified sign until the monthly age-out.
  const tally = await startFakeTally({ stockInHandBalance: '0.00' });
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const first = h.store.getQuirks()!;
    assert.equal((JSON.parse(first.json) as TallyQuirks).stockValueSign, 'unknown');

    h.advance(25 * 3600 * 1000);
    h.store.setWatermark({ companyGuid: 'guid-acme', altMstId: 1, altVchId: 1 }, Date.now());
    await h.cycle();

    assert.notEqual(
      h.store.getQuirks()!.probedAt,
      first.probedAt,
      'an open question must be re-asked within a day',
    );
  } finally {
    h.cleanup();
    await tally.close();
  }
});

// ---------------------------------------------------------------- the empty column

test('AN EMPTY PARTY COLUMN REFUSES TO SYNC, loudly', async () => {
  // THE characteristic Tally failure: a wrong method name returns blank cells, not an error.
  // Quirks are pre-seeded so this exercises assertBillsLookSane on the extraction path rather
  // than the prober — i.e. the case where a Tally upgrade breaks a dialect we had resolved.
  const tally = await startFakeTally({ partyNames: ['', ''] });
  const h = await harness({ port: tally.port });
  try {
    h.store.setQuirks({
      quirksSchemaVersion: QUIRKS_SCHEMA_VERSION,
      tallyVersion: 'unknown',
      probedAt: Date.parse('2026-07-16T09:59:00Z'),
      json: JSON.stringify(GOOD_QUIRKS),
    });

    await assert.rejects(() => h.cycle(), /every party name is empty|Refusing to sync/);

    assert.equal(h.uploads.length, 0, 'NOTHING may be published from a broken extraction');
    assert.equal(
      h.store.getWatermark('guid-acme'),
      undefined,
      'the watermark must not advance, or this change set is skipped forever',
    );
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('a half-broken party column is refused too', async () => {
  // Half the names is not "mostly working"; it is a dialect mismatch that happens to resolve
  // for some rows. Publishing it means a dashboard where some debtors silently vanish.
  const tally = await startFakeTally({
    bills: [
      ['Named Co', '2026-01-01', '0', '-100.00', '0', '5'],
      ['', '2026-01-01', '0', '-100.00', '0', '5'],
      ['', '2026-01-01', '0', '-100.00', '0', '5'],
    ],
  });
  const h = await harness({ port: tally.port });
  try {
    h.store.setQuirks({
      quirksSchemaVersion: QUIRKS_SCHEMA_VERSION,
      tallyVersion: 'unknown',
      probedAt: Date.parse('2026-07-16T09:59:00Z'),
      json: JSON.stringify(GOOD_QUIRKS),
    });
    await assert.rejects(() => h.cycle(), /only 1 have party names|Refusing to sync/);
    assert.equal(h.uploads.length, 0);
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('a business owed nothing syncs an empty ageing section rather than failing', async () => {
  // A cash-trade shop legitimately has no open bills. Refusing here would strand it.
  const tally = await startFakeTally({ bills: [], debtorsBalance: '0.00' });
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const ageing = await open(h, 'ageing_receivable');
    assert.deepEqual(ageing.rows, []);
    assert.deepEqual(ageing.totals, []);
  } finally {
    h.cleanup();
    await tally.close();
  }
});

// ---------------------------------------------------------------- gates

test('THE STEADY STATE: an unchanged company costs one probe and nothing else', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const requestsAfterFirst = tally.requests.length;
    const uploadsAfterFirst = h.uploads.length;

    h.advance(15 * 60 * 1000);
    await h.cycle();

    assert.equal(
      tally.requests.length,
      requestsAfterFirst + 1,
      'exactly one ~2KB probe, and no section pulled',
    );
    assert.equal(h.uploads.length, uploadsAfterFirst, 'and nothing uploaded');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('the hash gate blocks re-upload when AlterID moved but the data did not', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    await h.cycle();
    const uploadsAfterFirst = h.uploads.length;

    // Pretend a voucher was entered: same data, one higher AlterVchId than we stored. Masters
    // are left alone so the gate says 'partial' — a 'full' would legitimately reset the hashes
    // and prove nothing about this gate.
    h.store.setWatermark({ companyGuid: 'guid-acme', altMstId: 1200, altVchId: 3399 }, Date.now());
    h.advance(60_000);
    await h.cycle();

    assert.ok(tally.countOf('TSGroups') >= 2, 'we DID ask Tally, because AlterID moved');
    assert.equal(h.uploads.length, uploadsAfterFirst, 'but nothing changed, so nothing uploaded');
  } finally {
    h.cleanup();
    await tally.close();
  }
});

test('a probe row without a GUID is skipped, never synced under its name', async () => {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-8' });
      // A company with an empty GUID column: no identity, so no sync.
      res.end(
        '<ENVELOPE><F01>Nameless Co</F01><F02></F02><F03>1</F03><F04>1</F04>' +
          '<F05>20260401</F05><F06>20260716</F06><F07>1</F07><F08>Maharashtra</F08></ENVELOPE>',
      );
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  const h = await harness({ port });
  try {
    await h.cycle();
    assert.equal(h.uploads.length, 0);
  } finally {
    h.cleanup();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

// ---------------------------------------------------------------- upload

test('the uploader signs the exact bytes it sends, at the path the server verifies', async () => {
  const seen: Array<{ headers: http.IncomingHttpHeaders; url: string; body: string }> = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      seen.push({ headers: req.headers, url: req.url ?? '', body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    const device = await generateDeviceKeypair('dev_1');
    const upload = createUploader({
      serverUrl: `http://127.0.0.1:${port}`,
      deviceId: 'dev_1',
      deviceSecretKey: device.secretKey,
    });

    const res = await upload('{"hello":"world"}', 'guid|company|2026-07-16|abc');
    assert.deepEqual(res, { ok: true, retryable: false, status: 200 });

    assert.equal(seen[0]!.url, '/api/sync');
    assert.equal(seen[0]!.body, '{"hello":"world"}');
    assert.equal(seen[0]!.headers['x-tb-device'], 'dev_1');
    assert.ok(seen[0]!.headers['x-tb-signature']);
    assert.equal(seen[0]!.headers['idempotency-key'], 'guid|company|2026-07-16|abc');
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('HTTP STATUS MAPS TO RETRYABILITY: 5xx yes, 4xx no', async () => {
  // A 4xx is a revoked device, a bad signature, a full quota. Retrying cannot fix any of them,
  // and the data is not lost by giving up — the section hash only advances on ACK, so Tally
  // re-supplies it next cycle.
  let status = 500;
  const server = http.createServer((_req, res) => {
    res.writeHead(status);
    res.end('nope');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    const device = await generateDeviceKeypair('dev_1');
    const upload = createUploader({
      serverUrl: `http://127.0.0.1:${port}`,
      deviceId: 'dev_1',
      deviceSecretKey: device.secretKey,
    });

    for (const [code, retryable] of [
      [500, true],
      [502, true],
      [503, true],
      [400, false],
      [401, false],
      [403, false],
      [409, false],
      [413, false],
    ] as const) {
      status = code;
      const res = await upload('{}', 'k');
      assert.deepEqual(res, { ok: false, retryable, status: code }, `status ${code}`);
    }

    status = 204;
    assert.deepEqual(await upload('{}', 'k'), { ok: true, retryable: false, status: 204 });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('an unreachable server is retryable, not a crash', async () => {
  const server = http.createServer(() => {});
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((r) => server.close(() => r()));

  const device = await generateDeviceKeypair('dev_1');
  const upload = createUploader({
    serverUrl: `http://127.0.0.1:${port}`,
    deviceId: 'dev_1',
    deviceSecretKey: device.secretKey,
  });
  assert.deepEqual(await upload('{}', 'k'), { ok: false, retryable: true });
});

test('a lost ACK does not lose the section', async () => {
  const tally = await startFakeTally();
  const h = await harness({ port: tally.port });
  try {
    h.setUploadResult({ ok: false, retryable: true });
    await h.cycle();
    assert.equal(
      h.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'),
      undefined,
      'the hash must NOT advance without an ACK',
    );

    h.setUploadResult({ ok: true, retryable: false });
    h.advance(3 * 60 * 60 * 1000);
    await h.cycle();
    assert.ok(h.store.getSectionHash('guid-acme', 'group_balance', '2026-07-16'));
  } finally {
    h.cleanup();
    await tally.close();
  }
});
