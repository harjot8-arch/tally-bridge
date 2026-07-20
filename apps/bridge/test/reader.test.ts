import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { IsoDate, Section, SectionPayload } from '@tally-bridge/core';
import {
  generateIdentity,
  makeAad,
  sealSection,
  sodiumReady,
  type DeviceRoster,
} from '@tally-bridge/crypto';
import { buildCards, type ReaderInputs } from '../src/main/reader.ts';
import type { StoredSnapshot } from '../src/main/snapshots.ts';

/**
 * The reader — the production caller of `openSection`. The tests that matter are the two
 * arguments an attacker cares about: `trustedDevices` (a forged envelope must die against the
 * pinned roster, however self-consistent it is) and `expect` (an authentic envelope must die in
 * the wrong slot — which is exactly the check that a tautological `expect: env.aad` would
 * destroy; these tests fail under that mutation).
 */

const TENANT = 't_1';
const DEVICE = 'dev_001';
const AS_OF: IsoDate = '2026-07-16';
const GUID = 'guid-acme';

const sodium = await sodiumReady();
const identity = await generateIdentity();
const deviceKp = sodium.crypto_sign_keypair();
const attackerKp = sodium.crypto_sign_keypair();
const roster: DeviceRoster = [{ deviceId: DEVICE, publicKey: deviceKp.publicKey }];

let seq = 0;

async function makeSlot(
  section: Section,
  payload: SectionPayload,
  over: Partial<{
    slotCompany: string;
    slotSection: Section;
    slotAsOf: IsoDate;
    aadCompany: string;
    aadAsOf: IsoDate;
    tenantId: string;
    signer: Uint8Array;
    stripSig: boolean;
  }> = {},
): Promise<StoredSnapshot> {
  const aad = makeAad({
    tenantId: over.tenantId ?? TENANT,
    deviceId: DEVICE,
    companyGuid: over.aadCompany ?? GUID,
    section,
    asOf: over.aadAsOf ?? AS_OF,
    snapshotTs: 1_000_000,
    seq: ++seq,
  });
  const envelope = await sealSection(payload, aad, identity.publicKey, over.signer ?? deviceKp.privateKey);
  const wire: Record<string, unknown> = { ...envelope };
  if (over.stripSig) delete wire['sig'];
  return {
    companyGuid: over.slotCompany ?? over.aadCompany ?? GUID,
    section: over.slotSection ?? section,
    asOf: over.slotAsOf ?? over.aadAsOf ?? AS_OF,
    contentHash: envelope.contentHash,
    storedAt: 1,
    envelope: JSON.stringify(wire),
  };
}

const companyPayload: SectionPayload = {
  section: 'company',
  rows: [
    {
      companyGuid: GUID,
      name: 'Acme Traders',
      state: 'MH',
      booksFrom: '2025-04-01',
      lastVoucherDate: '2026-07-15',
      tallyFlavour: 'prime',
      tallyVersion: 'unknown',
    },
  ],
};

const cashPayload: SectionPayload = {
  section: 'cash_bank',
  rows: [
    // Dr negative: a healthy bank balance arrives with a minus sign and the card flips it.
    { companyGuid: GUID, asOf: AS_OF, ledgerName: 'HDFC CA 4471', parent: 'Bank Accounts', closing: '-1234.50' },
    { companyGuid: GUID, asOf: AS_OF, ledgerName: 'Cash', parent: 'Cash-in-Hand', closing: '-100.00' },
  ],
};

const ageingPayload: SectionPayload = {
  section: 'ageing_receivable',
  rows: [
    { companyGuid: GUID, asOf: AS_OF, side: 'receivable', partyName: 'Sharma & Sons', bucket: '0_30', amount: '-500.00', billCount: 2 },
  ],
  totals: [
    { companyGuid: GUID, asOf: AS_OF, side: 'receivable', bucket: '0_30', amount: '-500.00', billCount: 2 },
  ],
};

const revenuePayload: SectionPayload = {
  section: 'period_revenue',
  rows: [
    { companyGuid: GUID, period: '2026-07', groupName: 'Sales Accounts', parent: '', amount: '1000.00' },
    { companyGuid: GUID, period: '2026-06', groupName: 'Sales Accounts', parent: '', amount: '800.00' },
  ],
};

const stockPayload: SectionPayload = {
  section: 'stock_value',
  rows: [{ companyGuid: GUID, asOf: AS_OF, stockGroup: 'Widgets', closingValue: '-2000.00' }],
};

function inputs(slots: StoredSnapshot[], over: Partial<ReaderInputs> = {}): ReaderInputs {
  return {
    slots,
    unreadable: 0,
    tenantId: TENANT,
    identityPublicKey: identity.publicKey,
    identitySecretKey: identity.secretKey,
    roster,
    log: () => {},
    ...over,
  };
}

// ---------------------------------------------------------------- the happy path

test('the full pipeline: sealed snapshots become cards with the right numbers', async () => {
  const slots = [
    await makeSlot('company', companyPayload),
    await makeSlot('cash_bank', cashPayload),
    await makeSlot('ageing_receivable', ageingPayload),
    await makeSlot('period_revenue', revenuePayload),
    await makeSlot('stock_value', stockPayload),
  ];
  const r = await buildCards(inputs(slots));
  assert.equal(r.state, 'ready');
  if (r.state !== 'ready') return;
  assert.equal(r.incomplete, false);
  assert.equal(r.companies.length, 1);

  const c = r.companies[0]!;
  assert.equal(c.name, 'Acme Traders', 'the display name comes from the company section');
  assert.equal(c.companyGuid, GUID);

  // Cash: Dr-negative balances flipped, summed in integer paise.
  assert.equal(c.cashBank?.total.paise, 133_450);
  assert.equal(c.cashBank?.accounts[0]?.name, 'HDFC CA 4471');

  // Receivables: flipped positive, totals from totals[].
  assert.equal(c.receivables?.total.paise, 50_000);
  assert.equal(c.receivables?.side, 'receivable');

  // Profit: the LATEST period only is "current"; the one before is the baseline.
  assert.equal(c.profit?.current.paise, 100_000);
  assert.equal(c.profit?.previous.paise, 80_000);
  assert.equal(c.salesTrend?.points.length, 2);

  assert.equal(c.stock?.total.paise, 200_000);
});

// ---------------------------------------------------------------- authenticity

test('A SERVER-MINTED ENVELOPE IS REFUSED: sealed to idPK, hash-consistent, signed by a key the bundle never pinned', async () => {
  // Everything about this envelope is self-consistent — the server holds idPK and can build it.
  // The ONE thing it cannot do is sign with a key inside the passphrase-sealed roster.
  const forged = await makeSlot('cash_bank', cashPayload, { signer: attackerKp.privateKey });
  const genuine = await makeSlot('company', companyPayload);

  const r = await buildCards(inputs([forged, genuine]));
  assert.equal(r.state, 'ready');
  if (r.state !== 'ready') return;
  assert.equal(r.incomplete, true, 'a refused slot must be visible as an incomplete dashboard');
  assert.equal(r.companies[0]?.cashBank, undefined, 'the forged numbers must not render');
  assert.equal(r.companies[0]?.name, 'Acme Traders', 'the genuine section still renders');
});

test('an unsigned envelope is refused outright', async () => {
  const slot = await makeSlot('cash_bank', cashPayload, { stripSig: true });
  const r = await buildCards(inputs([slot, await makeSlot('company', companyPayload)]));
  assert.equal(r.state, 'ready');
  if (r.state !== 'ready') return;
  assert.equal(r.incomplete, true);
  assert.equal(r.companies[0]?.cashBank, undefined);
});

test('without the identity secret key nothing opens — the session is the only door to the numbers', async () => {
  const slots = [await makeSlot('cash_bank', cashPayload)];
  const wrongKey = new Uint8Array(32).fill(9);
  const r = await buildCards(inputs(slots, { identitySecretKey: wrongKey }));
  // Every slot fails to open; with nothing decrypted and failures present, this is an error
  // state, never a fabricated "empty".
  assert.equal(r.state, 'error');
});

// ---------------------------------------------------------------- expect: the question asked

test("EXPECT IS THE QUESTION, NOT THE ANSWER: company A's authentic envelope does not open in company B's slot", async () => {
  // Perfectly genuine envelope for company A... stored (or swapped) under company B's slot.
  // Every cryptographic check passes; the answer just does not answer the question. If the
  // reader passed env.aad back as `expect`, this would render A's numbers under B's name.
  const swapped = await makeSlot('cash_bank', cashPayload, { aadCompany: 'guid-OTHER', slotCompany: GUID });
  const r = await buildCards(inputs([swapped, await makeSlot('company', companyPayload)]));
  assert.equal(r.state, 'ready');
  if (r.state !== 'ready') return;
  assert.equal(r.incomplete, true);
  assert.equal(r.companies[0]?.cashBank, undefined);
});

test('a genuine envelope for the wrong SECTION is refused in this slot', async () => {
  const wrongSection = await makeSlot('stock_value', stockPayload, { slotSection: 'cash_bank' });
  const r = await buildCards(inputs([wrongSection]));
  assert.equal(r.state, 'error');
});

test('a genuine envelope for the wrong AS-OF DATE is refused in this slot', async () => {
  const stale = await makeSlot('cash_bank', cashPayload, { aadAsOf: '2026-07-01', slotAsOf: AS_OF });
  const r = await buildCards(inputs([stale]));
  assert.equal(r.state, 'error');
});

test("an envelope for a different tenant is refused — this install's tenantId is part of the question", async () => {
  const otherTenant = await makeSlot('cash_bank', cashPayload, { tenantId: 't_2' });
  const r = await buildCards(inputs([otherTenant]));
  assert.equal(r.state, 'error');
});

// ---------------------------------------------------------------- failure shape

test('a bad amount loses ONE card loudly, not the whole company quietly', async () => {
  const badCash: SectionPayload = {
    section: 'cash_bank',
    rows: [{ companyGuid: GUID, asOf: AS_OF, ledgerName: 'X', parent: '', closing: 'not money' }],
  };
  const slots = [
    await makeSlot('company', companyPayload),
    await makeSlot('cash_bank', badCash),
    await makeSlot('stock_value', stockPayload),
  ];
  const r = await buildCards(inputs(slots));
  assert.equal(r.state, 'ready');
  if (r.state !== 'ready') return;
  assert.equal(r.incomplete, true, 'the missing card must be declared');
  assert.equal(r.companies[0]?.cashBank, undefined, 'the coerced number must not render');
  assert.equal(r.companies[0]?.stock?.total.paise, 200_000, 'the good card survives');
});

test('no snapshots and no failures is EMPTY; no snapshots with unreadable files is an ERROR', async () => {
  assert.deepEqual(await buildCards(inputs([])), { state: 'empty' });
  const r = await buildCards(inputs([], { unreadable: 2 }));
  assert.equal(r.state, 'error');
});

test('nothing the reader returns carries a stack trace or an exception message', async () => {
  const forged = await makeSlot('cash_bank', cashPayload, { signer: attackerKp.privateKey });
  const r = await buildCards(inputs([forged]));
  const text = JSON.stringify(r);
  assert.ok(!/at\s+\w+\s+\(/.test(text), 'no stack frames');
  assert.ok(!text.includes('Error'), 'no error class names');
  assert.ok(!text.toLowerCase().includes('signature'), 'no crypto internals in the surface');
});
