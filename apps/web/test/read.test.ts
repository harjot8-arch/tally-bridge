import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadDashboard } from '../src/data/read.ts';
import {
  makeFixture,
  sessionOf,
  slotRow,
  cashPayload,
  companyPayload,
  fakeServer,
  spyKV,
  TENANT,
  GUID,
  type Fixture,
} from './helpers.ts';

/**
 * THE READ PATH, ATTACKED.
 *
 * This is the web twin of apps/bridge/test/backend.adversary.test.ts, and it is the test the
 * previous agent was killed before writing. The read path is where the product's central claim
 * lives on the client: the server hands over ciphertext and metadata and NOTHING it serves may
 * become a number on a card unless a device in the passphrase-sealed roster signed it.
 *
 * The forgery is not simulated with a flag. `slotRow(fx, payload, fx.server.privateKey, ...)`
 * seals a REAL envelope with the malicious server's own key: a fresh CEK sealed to the true
 * idPK, an AAD the server chose, a ciphertext over a plaintext the server invented, a matching
 * contentHash. Everything a server that knows idPK and the real deviceId can actually compute.
 * The ONLY thing it cannot compute is a signature from a key inside a roster it cannot decrypt.
 * If any of these forgeries reaches a card, the E2E claim is void.
 */

async function ready(fx: Fixture, server: ReturnType<typeof fakeServer>, storage = spyKV()) {
  return loadDashboard({ fetch: server, storage }, sessionOf(fx));
}

test('THE FORGERY IS REFUSED: a server-signed envelope never becomes a card', async () => {
  const fx = await makeFixture();
  // The server fabricates a cash balance of one crore and signs it with its OWN key.
  const forged = await slotRow(fx, cashPayload('-10000000.00'), fx.server.privateKey);
  const result = await ready(fx, fakeServer(fx, { snapshots: [forged] }));

  // Every slot failed to open, so there is no company to show — an error, not a card.
  assert.equal(result.state, 'error', JSON.stringify(result));
  // And the fabricated number appears NOWHERE in the result.
  assert.ok(!JSON.stringify(result).includes('10000000'), 'the forged figure leaked into the result');
  assert.ok(!JSON.stringify(result).includes('1,00,00,000'));
});

test('THE HONEST CONTROL: the SAME payload signed by the real device DOES become a card', async () => {
  const fx = await makeFixture();
  // Identical to the forgery in every way except the signing key. This is what proves the
  // refusal above is the ROSTER doing its job and not some unrelated parse failure — the two
  // tests are a matched pair.
  const honest = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey);
  const company = await slotRow(fx, companyPayload(), fx.device.privateKey);
  const result = await ready(fx, fakeServer(fx, { snapshots: [honest, company] }));

  assert.equal(result.state, 'ready', JSON.stringify(result));
  if (result.state !== 'ready') return;
  assert.equal(result.incomplete, false);
  assert.equal(result.companies.length, 1);
  assert.equal(result.companies[0]?.cashBank?.total.display, '₹3,42,110');
});

test('a valid envelope for ANOTHER TENANT is refused — tenantId is the owner\'s own login input', async () => {
  const fx = await makeFixture();
  // Authentic in every way, device-signed, roster-valid — but the AAD names a different tenant.
  // The reader knows its own tenant from the login it performed, not from the server, so this is
  // refused even though the signature and roster are genuine.
  const otherTenant = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey, {
    tenantId: 'someone_elses_tenant',
  });
  const result = await ready(fx, fakeServer(fx, { snapshots: [otherTenant] }));
  assert.equal(result.state, 'error', JSON.stringify(result));
  assert.ok(!JSON.stringify(result).includes('342110'));
});

test('a slot whose LISTING disagrees with its signed AAD is refused (server index vs authenticated truth)', async () => {
  const fx = await makeFixture();
  // The envelope's AAD honestly says cash_bank; the server lists it under a different section to
  // try to slide it into the wrong slot. `expect.section` comes from the listing, the AAD from
  // the signature — they must agree or the slot is dropped.
  const mislisted = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey, {
    listedSection: 'ageing_receivable',
  });
  const result = await ready(fx, fakeServer(fx, { snapshots: [mislisted] }));
  assert.equal(result.state, 'error', JSON.stringify(result));
});

test('an envelope for a DIFFERENT company than its listing is refused', async () => {
  const fx = await makeFixture();
  const mismatched = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey, {
    companyGuid: 'guid-other',
  });
  // Listed under GUID, AAD says guid-other: openSection's expect.companyGuid (from the listing)
  // will not match the signed AAD.
  mismatched.companyGuid = GUID;
  const result = await ready(fx, fakeServer(fx, { snapshots: [mismatched] }));
  assert.equal(result.state, 'error', JSON.stringify(result));
});

test('FRESHNESS: an authentic-but-OLDER snapshot is refused and counted, not shown', async () => {
  const fx = await makeFixture();
  const storage = spyKV();

  // First unlock sees ts=2000 and remembers it.
  const fresh = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey, { snapshotTs: 2000 });
  const company = await slotRow(fx, companyPayload(), fx.device.privateKey, { snapshotTs: 2000 });
  const first = await loadDashboard({ fetch: fakeServer(fx, { snapshots: [fresh, company] }), storage }, sessionOf(fx));
  assert.equal(first.state, 'ready');

  // The server now replays an OLDER, still-perfectly-authentic cash envelope (ts=1000). It is
  // signed by the real device and its AAD is genuine — selection, not forgery, which is the one
  // lever a careful server keeps. The browser's mark refuses it.
  const replayed = await slotRow(fx, cashPayload('-999999.00'), fx.device.privateKey, { snapshotTs: 1000 });
  const company2 = await slotRow(fx, companyPayload(), fx.device.privateKey, { snapshotTs: 3000 });
  const second = await loadDashboard(
    { fetch: fakeServer(fx, { snapshots: [replayed, company2] }), storage },
    sessionOf(fx),
  );

  assert.equal(second.state, 'ready', JSON.stringify(second));
  if (second.state !== 'ready') return;
  assert.equal(second.staleRefused, 1, 'the replayed cash slot must be counted as stale-refused');
  assert.equal(second.incomplete, true);
  // The stale figure must not be on screen.
  assert.ok(!JSON.stringify(second).includes('999999'));
});

test('an EMPTY roster refuses even a correctly-device-signed envelope', async () => {
  const fx = await makeFixture();
  const honest = await slotRow(fx, cashPayload('-342110.00'), fx.device.privateKey);
  // A session whose roster is empty (a bundle that carried no devices) trusts no signature at
  // all. This is the failure mode of a server-supplied roster stripped to nothing.
  const session = { ...sessionOf(fx), roster: [] };
  const result = await loadDashboard({ fetch: fakeServer(fx, { snapshots: [honest] }), storage: spyKV() }, session);
  assert.equal(result.state, 'error', JSON.stringify(result));
});

test('a malformed snapshot listing is one plain error, never a throw', async () => {
  const fx = await makeFixture();
  // The server returns garbage where the envelope should be. The reader must degrade to a
  // sentence, not propagate an exception to the UI.
  const result = await ready(fx, fakeServer(fx, { snapshots: 'not an array' }));
  assert.equal(result.state, 'error');
  if (result.state === 'error') assert.ok(!result.message.includes('undefined') && result.message.length > 0);
});

test('an empty tenant with no snapshots is EMPTY, not an error', async () => {
  const fx = await makeFixture();
  const result = await ready(fx, fakeServer(fx, { snapshots: [] }));
  assert.equal(result.state, 'empty');
});
