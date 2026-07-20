import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_PAYLOAD_BYTES,
  MAX_TENANT_BYTES,
  MAX_UPLOADS_PER_HOUR_PER_DEVICE,
  checkQuota,
  quotaStatus,
  type QuotaState,
} from '../src/quota.ts';

const state = (over: Partial<QuotaState> = {}): QuotaState => ({
  payloadBytes: 2_048,
  uploadsInLastHour: 3,
  tenantBytesStored: 1_000_000,
  ...over,
});

test('a normal upload passes', () => {
  assert.deepEqual(checkQuota(state()), { ok: true });
});

test('each cap rejects at its own boundary', () => {
  assert.ok(checkQuota(state({ payloadBytes: MAX_PAYLOAD_BYTES })).ok, 'the limit itself is allowed');
  const tooBig = checkQuota(state({ payloadBytes: MAX_PAYLOAD_BYTES + 1 }));
  assert.ok(!tooBig.ok && tooBig.failure.kind === 'payload_too_large');

  const rateOk = checkQuota(state({ uploadsInLastHour: MAX_UPLOADS_PER_HOUR_PER_DEVICE - 1 }));
  assert.ok(rateOk.ok);
  const limited = checkQuota(state({ uploadsInLastHour: MAX_UPLOADS_PER_HOUR_PER_DEVICE }));
  assert.ok(!limited.ok && limited.failure.kind === 'rate_limited');

  const full = checkQuota(state({ tenantBytesStored: MAX_TENANT_BYTES + 1, payloadBytes: 1 }));
  assert.ok(!full.ok && full.failure.kind === 'tenant_quota_exceeded');
});

test('every quota failure maps to a 4xx/5xx the Bridge treats as non-retryable', () => {
  assert.equal(quotaStatus({ kind: 'payload_too_large', bytes: 1, limit: 1 }), 413);
  assert.equal(quotaStatus({ kind: 'rate_limited', uploadsInWindow: 1, limit: 1 }), 429);
  assert.equal(quotaStatus({ kind: 'tenant_quota_exceeded', bytes: 1, limit: 1 }), 507);
});

// ---------------------------------------------------------------- adversarial audit additions

test('AUDIT: NaN must not walk straight through every cap', () => {
  // THE BYPASS. `NaN > limit` is false, and so is every other comparison NaN takes part in --
  // so a NaN sails past all three checks and checkQuota returns ok:true. These caps are the
  // only thing between a compromised Bridge and an unrefundable overage on a small business's
  // own Neon bill, so failing OPEN on garbage is the one thing they must never do.
  //
  // Reachable the moment any caller derives a number from the wire: Number(contentLength) on a
  // missing header is NaN, and so is parseInt of a malformed one.
  const nan = checkQuota({ payloadBytes: NaN, uploadsInLastHour: NaN, tenantBytesStored: NaN });
  assert.ok(!nan.ok, 'NaN must be rejected, not waved through');

  assert.ok(!checkQuota(state({ payloadBytes: NaN })).ok);
  assert.ok(!checkQuota(state({ uploadsInLastHour: NaN })).ok);
  assert.ok(!checkQuota(state({ tenantBytesStored: NaN })).ok);
});

test('AUDIT: negative byte counts are rejected, not treated as headroom', () => {
  // Nothing legitimate produces these. A negative tenantBytesStored is a broken accounting
  // query, and silently reading it as "plenty of room left" is how the cap quietly stops
  // existing months before anyone notices the bill.
  assert.ok(!checkQuota(state({ payloadBytes: -1 })).ok);
  assert.ok(!checkQuota(state({ uploadsInLastHour: -1 })).ok);
  assert.ok(!checkQuota(state({ tenantBytesStored: -1 })).ok);
});

test('AUDIT: a FRACTIONAL count is not a count — Number.isFinite was the wrong guard', () => {
  // FOUND FAILING. `measurable` was `Number.isFinite(n) && n >= 0`, and ingest.ts says in so many
  // words, about its own fields: "Number.isFinite is not the check these need. It admits 1.5, -1
  // and 2^53+1." The same sentence applied here and this function was not obeying it.
  //
  // The live shape: reserveUpload returns 1.5, ingest subtracts one for `uploadsInLastHour: 0.5`,
  // 0.5 clears `>= 0`, then `0.5 >= 60` is false and the request is ADMITTED. Not the NaN
  // fail-open — a fractional one, which the NaN guard does not catch because 0.5 IS finite. All
  // three inputs are counts (a byte length, a row count, a SUM over BIGINT); a fractional one
  // means the accounting is broken, and a broken count must answer "no", never "yes".
  assert.ok(!checkQuota(state({ uploadsInLastHour: 1.5 })).ok, 'a fractional upload count is not headroom');
  assert.ok(!checkQuota(state({ payloadBytes: 2048.5 })).ok);
  assert.ok(!checkQuota(state({ tenantBytesStored: 1_000_000.5 })).ok);
  const r = checkQuota(state({ uploadsInLastHour: 0.5 }));
  assert.equal(r.ok ? '' : r.failure.kind, 'unmeasurable');
});

test('AUDIT: a count past the safe-integer range cannot be compared exactly, so it is refused', () => {
  // Beyond 2^53-1 the `>=` chain stops being exact. A cap that cannot compare exactly is not a
  // cap, and the honest answer to a count that large is "unmeasurable", not a guess.
  //
  // ASSERT THE KIND, NOT MERELY `!ok`. Written as `assert.ok(!checkQuota(...).ok)` this test is
  // VACUOUS: 2^53 is over the rate cap and over the tenant cap, so it comes back `!ok` whether it
  // was REFUSED AS UNMEASURABLE or merely rate_limited — it passes identically against the
  // Number.isFinite version this is meant to pin against. The kind is the only thing that
  // distinguishes "we refused to compare it" from "we compared it and it happened to be big".
  const rate = checkQuota(state({ uploadsInLastHour: 2 ** 53 }));
  assert.equal(rate.ok ? '' : rate.failure.kind, 'unmeasurable');
  const bytes = checkQuota(state({ tenantBytesStored: 2 ** 53 }));
  assert.equal(bytes.ok ? '' : bytes.failure.kind, 'unmeasurable');
});

test('AUDIT: the tenant cap counts the payload being admitted, not just what is stored', () => {
  // Checking only what is ALREADY stored admits one full payload past the ceiling every time.
  // The tenant is at the line; this upload must not be the one that crosses it.
  const r = checkQuota({
    payloadBytes: MAX_PAYLOAD_BYTES,
    uploadsInLastHour: 0,
    tenantBytesStored: MAX_TENANT_BYTES,
  });
  assert.ok(!r.ok && r.failure.kind === 'tenant_quota_exceeded');
});
