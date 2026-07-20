/**
 * Upload caps.
 *
 * These are not abuse-prevention in the usual sense — the attacker here is a stolen device
 * signing key, and the victim is the CLIENT'S OWN Neon bill. There is no free way to undo a
 * $400 overage on a small business's card, and the client owns the account, so a runaway
 * uploader is a real financial loss with no refund path. The caps are the only thing standing
 * between a compromised Bridge and that bill.
 */

/** A sealed section for this product is single-digit KB; 1MB is already three orders of slack. */
export const MAX_PAYLOAD_BYTES = 1_048_576;

/** 15-minute polling across a handful of sections; 60/hr leaves room for backfill and retries. */
export const MAX_UPLOADS_PER_HOUR_PER_DEVICE = 60;

/** A full snapshot is <100KB. A tenant exceeding this is malfunctioning or malicious. */
export const MAX_TENANT_BYTES = 500 * 1024 * 1024;

export type QuotaFailure =
  | { kind: 'payload_too_large'; bytes: number; limit: number }
  | { kind: 'rate_limited'; uploadsInWindow: number; limit: number }
  | { kind: 'tenant_quota_exceeded'; bytes: number; limit: number }
  | { kind: 'unmeasurable'; detail: string };

export type QuotaResult = { ok: true } | { ok: false; failure: QuotaFailure };

export interface QuotaState {
  payloadBytes: number;
  uploadsInLastHour: number;
  tenantBytesStored: number;
}

/**
 * A count we can actually enforce against.
 *
 * THE BYPASS THIS CLOSES: every check below is a `>` or `>=`, and every comparison involving
 * NaN is false. So a single NaN — `Number(req.headers['content-length'])` with the header
 * absent, a `SUM()` over an empty table, a malformed body — walks through ALL THREE caps and
 * checkQuota returns ok. The caps fail OPEN on garbage, which is the one thing they must never
 * do: they are the only thing between a compromised Bridge and an overage on the CLIENT'S own
 * Neon card, and there is no refund path for that.
 *
 * Negatives are rejected for the same reason rather than clamped: nothing legitimate produces
 * one, so it means the accounting is broken — and a broken accounting query reading as
 * "plenty of headroom" is how a cap silently stops existing months before the bill lands.
 *
 * `Number.isSafeInteger`, NOT `Number.isFinite` — and ingest.ts already says why, about its own
 * fields: "Number.isFinite is not the check these need. It admits 1.5, -1 and 2^53+1." That
 * sentence was true here too and this function was not obeying it. All three of these are COUNTS
 * — a byte length, a row count, a SUM over a BIGINT column — so a fractional one is not a small
 * number, it is a broken accounting query, and `Number.isFinite` let it through: 1.5 passed
 * `>= 0`, became `uploadsInLastHour: 0.5`, compared as false against every cap and was ADMITTED.
 * That is the same fail-open shape as the NaN above, one step less obvious, and the safe answer
 * to "this count is not a count" is no. 2^53 is refused for the matching reason: past the safe
 * integer range the comparisons stop being exact, and a cap that cannot compare exactly is not a
 * cap.
 */
function measurable(n: number): boolean {
  return Number.isSafeInteger(n) && n >= 0;
}

export function checkQuota(state: QuotaState): QuotaResult {
  // Validate first. A number we cannot compare is not a number we can enforce against, and the
  // safe answer to "I cannot measure this" is no, not yes.
  for (const [name, value] of [
    ['payloadBytes', state.payloadBytes],
    ['uploadsInLastHour', state.uploadsInLastHour],
    ['tenantBytesStored', state.tenantBytesStored],
  ] as const) {
    if (!measurable(value)) {
      return {
        ok: false,
        failure: { kind: 'unmeasurable', detail: `${name} is not a usable count: ${value}` },
      };
    }
  }

  if (state.payloadBytes > MAX_PAYLOAD_BYTES) {
    return {
      ok: false,
      failure: { kind: 'payload_too_large', bytes: state.payloadBytes, limit: MAX_PAYLOAD_BYTES },
    };
  }
  if (state.uploadsInLastHour >= MAX_UPLOADS_PER_HOUR_PER_DEVICE) {
    return {
      ok: false,
      failure: {
        kind: 'rate_limited',
        uploadsInWindow: state.uploadsInLastHour,
        limit: MAX_UPLOADS_PER_HOUR_PER_DEVICE,
      },
    };
  }
  // Count the payload being ADMITTED, not just what is already stored. Checking the stored
  // figure alone lets every single upload land one full payload past the ceiling — the cap is
  // meant to be a ceiling, not a trigger that fires once you are already over it.
  const afterThisUpload = state.tenantBytesStored + state.payloadBytes;
  if (afterThisUpload > MAX_TENANT_BYTES) {
    return {
      ok: false,
      failure: {
        kind: 'tenant_quota_exceeded',
        bytes: afterThisUpload,
        limit: MAX_TENANT_BYTES,
      },
    };
  }
  return { ok: true };
}

/**
 * Map a quota failure to an HTTP status.
 *
 * All of these are 4xx and therefore NON-RETRYABLE, which the Bridge's outbox reads as "drop
 * it, don't back off". That is correct and load-bearing: a rate-limited Bridge that retried
 * would defeat the cap that exists to protect the bill.
 *
 * WHY THE DATA COMES BACK, STATED CORRECTLY. This comment used to say "the section hash is only
 * advanced on ACK, so the data re-enqueues on the next healthy cycle." The conclusion was right
 * by accident and the REASON was wrong, which is worse than being simply wrong: the hash is not
 * the only gate. The WATERMARK is advanced at ENQUEUE time, and `decideGate` consults the
 * watermark FIRST — so a dropped row whose watermark had already moved would cause the company
 * to be skipped on every subsequent cycle, extract() would never run, and the section would
 * re-enqueue on NO cycle. The owner would read a frozen number under a green checkmark.
 *
 * What actually makes the claim true is that `drainOutbox` calls `SyncStore.invalidateWatermark()`
 * on the abandon path (see the comment there). The next cycle then finds no watermark, decides
 * `full`, and re-pulls. If that call is ever removed, this paragraph becomes a lie again and the
 * failure is silent — which is why the reason, not just the conclusion, is written down here.
 */
export function quotaStatus(f: QuotaFailure): number {
  switch (f.kind) {
    case 'payload_too_large':
      return 413;
    case 'rate_limited':
      return 429;
    case 'tenant_quota_exceeded':
      return 507;
    // 400, and deliberately not 500: the request could not be measured, which is a fact about
    // what arrived, not about the server being broken. It is also non-retryable, which is
    // correct — an unmeasurable request will be exactly as unmeasurable next time.
    case 'unmeasurable':
      return 400;
  }
}
