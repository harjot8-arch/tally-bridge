import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { TallyResult } from '@tally-bridge/tally';
import { detectTally, probeCompanyList, type ProbeTransport } from '../src/main/detect.ts';

/**
 * detectTally: every Tally condition becomes a sentence and a boolean, never an exception and
 * never an HTTP status. The two "normal life" states — closed overnight, open with no books —
 * must not read as errors.
 */

function fake(result: TallyResult, encoding: string | undefined = 'utf16le'): ProbeTransport & { detected: number } {
  const t = {
    currentEncoding: encoding,
    detected: 0,
    detectEncoding: async () => {
      t.detected++;
      return undefined;
    },
    request: async () => result,
  };
  return t;
}

/** Probe rows: F01 name, F02 guid, F07 isActive — 8 fields per the request schema. */
const twoCompaniesXml =
  '<ENVELOPE>' +
  '<F01>Acme Traders</F01><F02>guid-1</F02><F03>10</F03><F04>20</F04><F05>20250401</F05><F06>20260715</F06><F07>1</F07><F08>MH</F08>' +
  '<F01>Beta & Co <Pune></F01><F02>guid-2</F02><F03>1</F03><F04>2</F04><F05>20250401</F05><F06>20260701</F06><F07>0</F07><F08>MH</F08>' +
  '</ENVELOPE>';

test('Tally closed (ECONNREFUSED) is "not open", reachable false — the normal overnight state, not an error', async () => {
  const r = await detectTally(fake({ ok: false, failure: { kind: 'not_running' } }));
  assert.deepEqual(r, { reachable: false, message: 'Tally is not open on this computer.', companies: [] });
});

test('an empty 200 body means Tally is up with no books open — reachable TRUE', async () => {
  const r = await detectTally(fake({ ok: false, failure: { kind: 'no_company_open' } }));
  assert.equal(r.reachable, true);
  assert.equal(r.message, 'Tally is open, but no company is loaded.');
});

test('a non-Tally answer on port 9000 names the real problem: something else owns the port', async () => {
  const r = await detectTally(fake({ ok: false, failure: { kind: 'not_tally', bodyExcerpt: '<html>' } }));
  assert.equal(r.reachable, false);
  assert.match(r.message, /port/);
  assert.ok(!r.message.includes('<'), 'the hostile body excerpt must not be echoed');
});

test('companies are parsed from a real probe shape, hostile names and all', async () => {
  const r = await detectTally(fake({ ok: true, xml: twoCompaniesXml }));
  assert.equal(r.reachable, true);
  assert.equal(r.companies.length, 2);
  assert.deepEqual(r.companies[0], { guid: 'guid-1', name: 'Acme Traders', isActive: true });
  assert.deepEqual(r.companies[1], { guid: 'guid-2', name: 'Beta & Co <Pune>', isActive: false });
  assert.match(r.message, /2 companies/);
});

test('a probe row with no GUID has no identity and is skipped', async () => {
  const xml =
    '<ENVELOPE>' +
    '<F01>Ghost Co</F01><F03>1</F03><F04>1</F04><F05>20250401</F05><F06>20260701</F06><F07>1</F07><F08>MH</F08>' +
    '</ENVELOPE>';
  const r = await detectTally(fake({ ok: true, xml }));
  assert.equal(r.companies.length, 0);
  assert.equal(r.message, 'Tally is open, but no company is loaded.');
});

test("Tally's own fault text is sanitised: no markup, clipped, terminated", async () => {
  const r = await detectTally(
    fake({ ok: false, failure: { kind: 'tally_error', message: '<LINEERROR>Licence not active ' + 'x'.repeat(300) } }),
  );
  assert.equal(r.reachable, true);
  assert.ok(!r.message.includes('<'), 'markup stripped');
  assert.ok(r.message.length < 160, 'clipped to banner size');
});

test('timeout / http / network failures each get a plain sentence with no status code', async () => {
  for (const failure of [
    { kind: 'timeout', afterMs: 10_000 },
    { kind: 'http_status', status: 502 },
    { kind: 'network', message: 'read ECONNRESET' },
  ] as const) {
    const r = await detectTally(fake({ ok: false, failure }));
    assert.equal(r.reachable, false);
    assert.ok(!/\d{3}/.test(r.message), `no status codes in: ${r.message}`);
    assert.ok(!r.message.includes('ECONNRESET'), 'no errno text');
  }
});

test('a throwing transport becomes one sentence, never a rejection', async () => {
  const t: ProbeTransport = {
    currentEncoding: 'utf16le',
    detectEncoding: async () => undefined,
    request: async () => {
      throw new Error('TypeError: cannot read properties of undefined');
    },
  };
  const r = await detectTally(t); // a rejection here fails the test run
  assert.equal(r.reachable, false);
  assert.ok(!r.message.includes('TypeError'));
});

test('the encoding is settled once before the probe when unknown', async () => {
  // '' rather than undefined: an explicit undefined would trigger the default parameter and
  // silently test the wrong branch. Falsy is what the production check keys on.
  const t = fake({ ok: false, failure: { kind: 'not_running' } }, '');
  await detectTally(t);
  assert.equal(t.detected, 1);
  const t2 = fake({ ok: false, failure: { kind: 'not_running' } }, 'utf8');
  await detectTally(t2);
  assert.equal(t2.detected, 0, 'a cached encoding is not re-probed');
});

test('probeCompanyList (the wizard-shared primitive) passes failures through untranslated', async () => {
  const r = await probeCompanyList(fake({ ok: false, failure: { kind: 'no_company_open' } }));
  assert.deepEqual(r, { ok: false, failure: { kind: 'no_company_open' } });
});
