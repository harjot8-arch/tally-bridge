import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { TallyTransport } from '../src/transport.ts';
import { QUIRKS_SCHEMA_VERSION, probeCapabilities, shouldReprobe } from '../src/flavour.ts';

/**
 * A configurable Tally impersonator.
 *
 * The point of these tests: the runtime prober must find the working TDL dialect on a Tally
 * build nobody has ever tested against. We cannot get those builds — but we CAN construct a
 * server that behaves like each hypothesis and assert the prober converges on it. This is what
 * turns "the ageing query is an unresolved unknown" into "the product resolves it itself."
 */
interface FakeTallyConfig {
  /** Only this collection type returns rows. */
  worksWithCollection: 'Bills' | 'Bill';
  /** Only this party method populates the party column. */
  worksWithParty: '$PartyName' | '$LedgerName' | '$..Name';
  /** Sundry Debtors closing balance — the oracle that says bills MUST exist. */
  debtorsBalance: string;
  /** Whether $_PrimaryGroup resolves. */
  primaryGroup: boolean;
  bankAccountsBalance?: string;
  /** Whether the reserved $$GroupBank functions resolve. */
  groupBankWorks?: boolean;
  /**
   * THE unverifiable, made switchable.
   *
   * Does Tally emit `<F03></F03>` for a blank field, or omit the tag entirely? Nobody knows
   * without a real Tally, and the answer used to decide whether the parser worked at all. Now
   * both hypotheses are testable, so the product no longer has to bet on one.
   */
  omitBlankTags?: boolean;
  /**
   * Model H1: `$$NumValue` is signed rather than a magnitude, with Tally's usual internal
   * Dr-positive convention. `expr.amount` negates on the debit branch ONLY, so this does not
   * invert the book — it drags every CREDIT negative and leaves debits right by accident.
   * The likeliest way every number in the product ends up wrong.
   */
  invertedSigns?: boolean;
  /** Adds a Stock-in-Hand group row (this closing balance) to the chart of accounts. */
  stockInHandBalance?: string;
  /**
   * Closing values the StockGroup collection returns — THE doubtful idiom, made switchable.
   * Whether `$$IsDebit` fires on a computed `$ClosingValue` is unverifiable from a desk, so
   * both hypotheses (values arrive Dr-negative like ledgers; values arrive as positive
   * magnitudes) are constructible here. Absent = an empty response, i.e. no inventory.
   */
  stockValues?: string[];
}

function fakeTally(cfg: FakeTallyConfig) {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const send = (xml: string) => {
        res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-8' });
        res.end(xml);
      };

      // --- Company probe
      if (body.includes('<ID>TSProbe</ID>')) {
        send(
          '<ENVELOPE><F01>Acme Traders</F01><F02>guid-acme</F02><F03>1200</F03><F04>3400</F04>' +
            '<F05>20260401</F05><F06>20260716</F06><F07>1</F07><F08>Maharashtra</F08></ENVELOPE>',
        );
        return;
      }

      // --- The oracle: chart of accounts
      if (body.includes('<ID>TSGroups</ID>')) {
        // A blank field is either an empty tag or no tag at all — that is the open question.
        const cell = (tag: string, v: string) =>
          v === '' && cfg.omitBlankTags ? '' : `<${tag}>${v}</${tag}>`;
        const pg = (v: string) => cell('F03', cfg.primaryGroup ? v : '');
        // Dr negative, Cr positive. H1 negates the CREDIT side only — see invertedSigns.
        const amt = (v: string, normal?: 'credit') =>
          cfg.invertedSigns && normal === 'credit' ? String(-Number(v)) : v;
        const row = (
          name: string,
          parent: string,
          primary: string,
          rev: string,
          close: string,
          normal?: 'credit',
        ) =>
          `<F01>${name}</F01>${cell('F02', parent)}${pg(primary)}<F04>${rev}</F04>` +
          `<F05>0.00</F05><F06>${amt(close, normal)}</F06><F07>0</F07>`;
        send(
          '<ENVELOPE>' +
            row('Sundry Debtors', 'Current Assets', 'Current Assets', '0', cfg.debtorsBalance) +
            row('Bank Accounts', 'Current Assets', 'Current Assets', '0', cfg.bankAccountsBalance ?? '0.00') +
            row('Cash-in-Hand', 'Current Assets', 'Current Assets', '0', '-125000.00') +
            (cfg.stockInHandBalance !== undefined
              ? row('Stock-in-Hand', 'Current Assets', 'Current Assets', '0', cfg.stockInHandBalance)
              : '') +
            row('Sales Accounts', '', 'Sales Accounts', '1', '500000.00', 'credit') +
            row('Direct Income', '', 'Direct Income', '1', '40000.00', 'credit') +
            '</ENVELOPE>',
        );
        return;
      }

      // --- Stock groups: the second unverifiable sign idiom
      if (body.includes('<ID>TSStock</ID>')) {
        send(
          '<ENVELOPE>' +
            (cfg.stockValues ?? []).map((v, i) => `<F01>Stock ${i}</F01><F02>${v}</F02>`).join('') +
            '</ENVELOPE>',
        );
        return;
      }

      // --- Cash/bank
      if (body.includes('<ID>TSCashBank</ID>')) {
        const usesReserved = body.includes('$$GroupBank');
        if (usesReserved && cfg.groupBankWorks === false) {
          send('<ENVELOPE></ENVELOPE>');
          return;
        }
        send('<ENVELOPE><F01>HDFC CA 4471</F01><F02>Bank Accounts</F02><F03>342110.75</F03></ENVELOPE>');
        return;
      }

      // --- The bills collection: the actual unknown
      if (body.includes('<ID>TSBills</ID>')) {
        const askedCollection = /<TYPE>(Bills|Bill)<\/TYPE>/.exec(body)?.[1];
        if (askedCollection !== cfg.worksWithCollection) {
          // Wrong collection type: Tally returns nothing at all.
          send('<ENVELOPE></ENVELOPE>');
          return;
        }
        // Right collection. Does the party method resolve?
        const askedParty = ['$PartyName', '$LedgerName', '$..Name'].find((m) =>
          body.includes(`<SET>${m}</SET>`),
        );
        const party = askedParty === cfg.worksWithParty ? 'A &amp; B Traders' : '';
        // THE characteristic failure: rows come back, the party column is silently empty.
        send(
          '<ENVELOPE>' +
            `<F01>${party}</F01><F02>2026-01-01</F02><F03>30</F03><F04>125000.00</F04><F05>0</F05><F06>90</F06>` +
            `<F01>${party ? 'Zed Enterprises' : ''}</F01><F02>2026-02-01</F02><F03>0</F03><F04>5000.00</F04><F05>0</F05><F06>10</F06>` +
            '</ENVELOPE>',
        );
        return;
      }

      send('<ENVELOPE></ENVELOPE>');
    });
  };
}

async function withFake(cfg: FakeTallyConfig, fn: (port: number) => Promise<void>) {
  const server = http.createServer(fakeTally(cfg));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(port);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const ctx = { company: 'Acme Traders', booksFrom: '2026-04-01', asOf: '2026-07-16' };

test('finds the documented default when that is what Tally speaks', async () => {
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.billsCollectionType, 'Bills');
      assert.equal(q.billPartyMethod, '$PartyName');
      assert.equal(q.supportsPrimaryGroupMethod, true);
    },
  );
});

test('THE payoff: converges on a dialect nobody predicted (Bill + $LedgerName)', async () => {
  // This is the build that would have shipped broken. The documented default returns nothing,
  // and the "obvious" fallback returns rows with blank names. The prober must reject both and
  // keep going.
  await withFake(
    {
      worksWithCollection: 'Bill',
      worksWithParty: '$LedgerName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.billsCollectionType, 'Bill');
      assert.equal(q.billPartyMethod, '$LedgerName');
    },
  );
});

test('converges on parent traversal ($..Name) when that is the only thing that works', async () => {
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$..Name',
      debtorsBalance: '130000.00',
      primaryGroup: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.billPartyMethod, '$..Name');
    },
  );
});

test('rows with blank party names are REJECTED, not accepted', async () => {
  // The characteristic Tally failure. If the prober accepted the first variant that returned
  // rows, it would pick $PartyName here and publish a dashboard of blank debtors.
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$LedgerName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.notEqual(q.billPartyMethod, '$PartyName');
      assert.equal(q.billPartyMethod, '$LedgerName');
    },
  );
});

test('refuses to configure when debtors exist but no variant can read them', async () => {
  // Silence here would mean reporting zero receivables to a business that IS owed money.
  // Refusing to sync is the only honest option — a dashboard reading "Receivables: 0" is
  // worse than no dashboard, because the owner would believe it.
  //
  // Hand-rolled rather than using fakeTally(): this Tally has NO working variant at all, which
  // that helper cannot express.
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      res.writeHead(200);
      if (body.includes('<ID>TSGroups</ID>')) {
        res.end(
          '<ENVELOPE><F01>Sundry Debtors</F01><F02>Current Assets</F02><F03>Current Assets</F03>' +
            '<F04>0</F04><F05>0.00</F05><F06>130000.00</F06><F07>0</F07></ENVELOPE>',
        );
        return;
      }
      res.end('<ENVELOPE></ENVELOPE>');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await assert.rejects(
      () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
      /outstanding debtors.*no known bills collection|Refusing to sync/s,
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a business owed nothing still onboards, using the documented default', async () => {
  // Critical for cash-trade businesses. If the prober demanded evidence it can never get, a
  // shop that collects on delivery could never finish setup.
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '0.00', // nobody owes anything
      primaryGroup: true,
    },
    async (port) => {
      const server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          res.writeHead(200);
          if (body.includes('<ID>TSGroups</ID>')) {
            res.end(
              '<ENVELOPE><F01>Sundry Debtors</F01><F02>Current Assets</F02><F03>Current Assets</F03>' +
                '<F04>0</F04><F05>0.00</F05><F06>0.00</F06><F07>0</F07></ENVELOPE>',
            );
            return;
          }
          res.end('<ENVELOPE></ENVELOPE>');
        });
      });
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      const { port: p2 } = server.address() as AddressInfo;
      try {
        const q = await probeCapabilities(new TallyTransport({ port: p2, encoding: 'utf8' }), ctx);
        assert.equal(q.billsCollectionType, 'Bills');
        assert.ok(
          q.notes.some((n) => /Sundry Debtors is zero/.test(n)),
          'must record WHY it defaulted, so support can tell this apart from a real failure',
        );
      } finally {
        await new Promise<void>((r) => server.close(() => r()));
      }
      void port;
    },
  );
});

test('detects that $_PrimaryGroup does not resolve', async () => {
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: false,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.supportsPrimaryGroupMethod, false);
      assert.ok(q.notes.some((n) => /_PrimaryGroup/.test(n)));
    },
  );
});

test('falls back when reserved bank functions return nothing despite a bank balance', async () => {
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
      bankAccountsBalance: '342110.75',
      groupBankWorks: false,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.useGroupBankFunctions, false);
    },
  );
});

test('a cash-only business does not trigger the bank fallback', async () => {
  // No bank ledgers AND no bank balance: the silence is honest, not a bug.
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
      bankAccountsBalance: '0.00',
      groupBankWorks: false,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.useGroupBankFunctions, true);
    },
  );
});

test('a dead group collection aborts the probe rather than guessing', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end('<ENVELOPE></ENVELOPE>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await assert.rejects(
      () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
      /group collection returned no rows/,
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

// ------------------------------------------- the oracle, against the unverifiable hypotheses

test('RESIDUAL 2: the prober survives Tally OMITTING blank tags rather than emitting them', async () => {
  // The unknown that blocked this fix: if `$_PrimaryGroup` is unsupported and Tally omits <F03>
  // instead of returning it empty, every later column used to shift left — so the oracle read
  // `$IsDeemedPositive` ("0") as the Sundry Debtors closing balance and concluded the business
  // was owed NOTHING. The prober would then take the permissive branch and adopt the documented
  // default with total confidence, on a Tally whose dialect it never actually verified.
  //
  // Both hypotheses now decode identically, so the product does not need the answer.
  await withFake(
    {
      worksWithCollection: 'Bill',
      worksWithParty: '$LedgerName',
      debtorsBalance: '130000.00',
      primaryGroup: false,
      omitBlankTags: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.supportsPrimaryGroupMethod, false);
      // THE assertion: the debtors balance was still read from F06, so the prober knew bills had
      // to exist and kept hunting until it found the dialect that returns them.
      assert.equal(q.billsCollectionType, 'Bill');
      assert.equal(q.billPartyMethod, '$LedgerName');
    },
  );
});

test('RESIDUAL 2, the sharp end: omitted tags cannot turn a refusal into a silent default', async () => {
  // The same shift, where it actually costs money. With the columns shifted left, the oracle read
  // `$IsDeemedPositive` ("0") as the Sundry Debtors balance — so a business owed Rs 1.3 lakh
  // looked like a business owed nothing, and `probeBillsVariant` took the branch that shrugs and
  // adopts the documented default instead of the branch that refuses to sync. The dashboard then
  // reports "Receivables: 0" for ever, confidently.
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      res.writeHead(200);
      if (body.includes('<ID>TSGroups</ID>')) {
        // $_PrimaryGroup unsupported, and this Tally OMITS the tag rather than emptying it.
        res.end(
          '<ENVELOPE>' +
            '<F01>Sundry Debtors</F01><F02>Current Assets</F02>' +
            '<F04>0</F04><F05>0.00</F05><F06>-130000.00</F06><F07>0</F07>' +
            '<F01>Cash-in-Hand</F01><F02>Current Assets</F02>' +
            '<F04>0</F04><F05>0.00</F05><F06>-125000.00</F06><F07>0</F07>' +
            '</ENVELOPE>',
        );
        return;
      }
      res.end('<ENVELOPE></ENVELOPE>'); // no bills variant works
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await assert.rejects(
      () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
      /outstanding debtors|Refusing to sync/s,
      'a shifted oracle would have defaulted here instead of refusing',
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a chart of accounts with no Sundry Debtors group is unknown, not "owed nothing"', async () => {
  // The tri-state. `false` licenses the prober to shrug and default; `undefined` must not.
  // Reading "I could not tell" as "there is nothing outstanding" is how a business owed crores
  // gets a confident "Receivables: 0".
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      res.writeHead(200);
      if (body.includes('<ID>TSGroups</ID>')) {
        res.end(
          '<ENVELOPE><F01>Cash-in-Hand</F01><F02>Current Assets</F02><F03>Current Assets</F03>' +
            '<F04>0</F04><F05>0.00</F05><F06>-125000.00</F06><F07>0</F07></ENVELOPE>',
        );
        return;
      }
      res.end('<ENVELOPE></ENVELOPE>');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await assert.rejects(
      () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
      /no Sundry Debtors group to say whether that silence is honest/,
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('a structurally malformed oracle aborts the probe rather than half-reading it', async () => {
  // The oracle is what every other capability is judged against. A partial read of it is worse
  // than none: it would silently pick a wrong TDL dialect and nothing downstream would notice.
  const server = http.createServer((_req, res) => {
    res.writeHead(200);
    // A group named "<F02>" — the injection, in the one collection we cannot cross-check.
    res.end(
      '<ENVELOPE><F01>Sundry <F02> Debtors</F01><F02>Current Assets</F02><F03>x</F03>' +
        '<F04>0</F04><F05>0.00</F05><F06>-130000.00</F06><F07>0</F07></ENVELOPE>',
    );
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await assert.rejects(
      () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
      /structurally malformed|Refusing to guess/,
    );
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

// ---------------------------------------------------------------- the sign canary

test('a correctly-signed book records that its signs were CHECKED, not assumed', async () => {
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
    },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.amountSigns, 'ok');
      assert.ok(q.notes.some((n) => /signs agree/.test(n)));
    },
  );
});

test('THE CANARY: a Tally whose credits come back negative refuses to configure', async () => {
  // The highest-value unverifiable in the product: `expr.amount` is coherent only if $$NumValue
  // returns a magnitude. If it is signed, the debit-branch negation drags the CREDIT side
  // negative and the dashboard renders inside-out — silently, and confidently.
  //
  // Note what this Tally looks like: Cash-in-Hand has exactly the right sign. Any check that
  // demanded "nothing agrees" would shrug at this and let it ship. No desk research closes the
  // question; only a real book can, and this is a real book saying so.
  await withFake(
    {
      worksWithCollection: 'Bills',
      worksWithParty: '$PartyName',
      debtorsBalance: '130000.00',
      primaryGroup: true,
      invertedSigns: true,
    },
    async (port) => {
      await assert.rejects(
        () => probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx),
        /INVERTED|inside-out/,
      );
    },
  );
});

// ---------------------------------------------------------------- the stock sign

const billsOk = {
  worksWithCollection: 'Bills' as const,
  worksWithParty: '$PartyName' as const,
  debtorsBalance: '130000.00',
  primaryGroup: true,
};

test('a stock idiom that matches the verified group idiom is recorded as MEASURED, not assumed', async () => {
  await withFake(
    { ...billsOk, stockInHandBalance: '-6200000.00', stockValues: ['-4500000.00', '-1700000.00'] },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.stockValueSign, 'dr_negative');
      assert.ok(q.notes.some((n) => /Stock \$ClosingValue arrives Dr-negative/.test(n)));
    },
  );
});

test('THE STOCK CANARY: positive magnitudes against a Dr Stock-in-Hand are caught', async () => {
  // The shipping-blocking hypothesis: $$IsDebit does not fire for a StockGroup's computed
  // $ClosingValue, the extraction hands the card layer positives, stockCard flips them, and
  // every stock figure in the product renders negative. This Tally IS that hypothesis, and the
  // probe must come back saying "negate at extraction".
  await withFake(
    { ...billsOk, stockInHandBalance: '-6200000.00', stockValues: ['4500000.00', '1700000.00'] },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.stockValueSign, 'positive_magnitude');
      assert.ok(q.notes.some((n) => /POSITIVE magnitude/.test(n)));
    },
  );
});

test('a service business with no inventory is unknown — vacuous, never "verified ok"', async () => {
  await withFake({ ...billsOk, stockInHandBalance: '0.00' }, async (port) => {
    const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
    assert.equal(q.stockValueSign, 'unknown');
  });
});

test('material stock with no Stock-in-Hand reference is unknown, and says the default is ASSUMED', async () => {
  // Non-integrated books: inventory is maintained but closing stock was never journalized, so
  // the reserved group carries nothing. There is no trusted reference; one unverifiable signal
  // must not flip the extraction, and support must be able to see the assumption.
  await withFake({ ...billsOk, stockValues: ['4500000.00'] }, async (port) => {
    const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
    assert.equal(q.stockValueSign, 'unknown');
    assert.ok(q.notes.some((n) => /ASSUMED/.test(n)));
    assert.ok(
      q.notes.some((n) => /No Stock-in-Hand group/.test(n)),
      'absent reserved group and zero balance are different facts; the note must say which',
    );
  });
});

test('a credit-balance Stock-in-Hand is a suspect reference, not an oracle', async () => {
  // With both readings positive, "same sign" would verify the broken hypothesis via a broken
  // reference. The reference must carry its structural Dr sign before it may adjudicate.
  await withFake(
    { ...billsOk, stockInHandBalance: '6200000.00', stockValues: ['4500000.00'] },
    async (port) => {
      const q = await probeCapabilities(new TallyTransport({ port, encoding: 'utf8' }), ctx);
      assert.equal(q.stockValueSign, 'unknown');
      assert.ok(q.notes.some((n) => /suspect/.test(n)));
    },
  );
});

// ---------------------------------------------------------------- cache invalidation

test('re-probes when there is no cache', () => {
  assert.equal(shouldReprobe(undefined, { tallyVersion: '3.0', now: Date.now() }), true);
});

test('re-probes when Tally is upgraded', () => {
  const cached = { quirksSchemaVersion: QUIRKS_SCHEMA_VERSION, tallyVersion: '3.0', probedAt: Date.now() };
  assert.equal(shouldReprobe(cached, { tallyVersion: '4.0', now: Date.now() }), true);
});

test('re-probes when our own quirks schema changes', () => {
  const cached = { quirksSchemaVersion: 0, tallyVersion: '3.0', probedAt: Date.now() };
  assert.equal(shouldReprobe(cached, { tallyVersion: '3.0', now: Date.now() }), true);
});

test('re-probes after 30 days even if nothing appears to have changed', () => {
  // Tally upgrades in place and its version string is not always reliable.
  const now = Date.now();
  const cached = {
    quirksSchemaVersion: QUIRKS_SCHEMA_VERSION,
    tallyVersion: '3.0',
    probedAt: now - 31 * 24 * 3600 * 1000,
  };
  assert.equal(shouldReprobe(cached, { tallyVersion: '3.0', now }), true);
});

test('does not re-probe on every startup', () => {
  // Probing costs ~9 round trips against a single-threaded app the owner is typing into.
  const now = Date.now();
  const cached = { quirksSchemaVersion: QUIRKS_SCHEMA_VERSION, tallyVersion: '3.0', probedAt: now - 1000 };
  assert.equal(shouldReprobe(cached, { tallyVersion: '3.0', now }), false);
});

test('an unresolved stock sign ages out DAILY, not monthly', () => {
  // 'unknown' usually means the book had no inventory to judge. The first stocked month must
  // not spend 30 days rendering under an unverified sign, so the cache re-asks within a day —
  // this is the "re-probe when inventory appears" trigger, bounded at 24h of staleness.
  const now = Date.now();
  const base = { quirksSchemaVersion: QUIRKS_SCHEMA_VERSION, tallyVersion: '3.0' };
  const twoDaysAgo = now - 2 * 24 * 3600 * 1000;
  const twoHoursAgo = now - 2 * 3600 * 1000;

  assert.equal(
    shouldReprobe({ ...base, probedAt: twoDaysAgo, stockSignUnresolved: true }, { tallyVersion: '3.0', now }),
    true,
  );
  // Within the day, still cached — the probe must not run every cycle just because a book is
  // stockless.
  assert.equal(
    shouldReprobe({ ...base, probedAt: twoHoursAgo, stockSignUnresolved: true }, { tallyVersion: '3.0', now }),
    false,
  );
  // A RESOLVED sign keeps the monthly cadence; the short leash is only for the open question.
  assert.equal(
    shouldReprobe({ ...base, probedAt: twoDaysAgo, stockSignUnresolved: false }, { tallyVersion: '3.0', now }),
    false,
  );
  assert.equal(shouldReprobe({ ...base, probedAt: twoDaysAgo }, { tallyVersion: '3.0', now }), false);
});
