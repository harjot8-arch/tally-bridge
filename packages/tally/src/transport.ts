import http from 'node:http';
import {
  contentTypeFor,
  decodeTallyResponse,
  encodeTallyRequest,
  extractTallyError,
  looksLikeTallyResponse,
  type TallyEncoding,
} from './codec.ts';

export const DEFAULT_TALLY_PORT = 9000;

/**
 * Hard cap on a response body.
 *
 * Port 9000 has no authentication and the Bridge runs on a desktop the owner also browses the
 * web from, so whatever answers is UNTRUSTED INPUT — it chooses how many bytes to send, and
 * without a cap it chose how much of this machine's memory to consume. Buffering to an array
 * and concatenating at 'end' means a 10GB response is a 10GB allocation.
 *
 * The number is deliberately far above anything real and still far below dangerous: every
 * request here is narrow by design (the probe is ~2KB, a full sync is under 100KB, ~2,000 open
 * bills are ~80KB). Nothing legitimate is within three orders of magnitude of this, so the cap
 * can never fire on a real Tally, and a body that reaches it is by definition not Tally —
 * which is exactly what it is reported as.
 */
export const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

/**
 * Errors that mean "Tally dropped this connection", not "Tally is unreachable".
 *
 * FIELD-OBSERVED against a real TallyPrime: it answered the encoding probe and then reset the
 * very next connection — two back-to-back requests with no gap between them. Tally's listener
 * is embedded in a single-threaded desktop app; when it is not ready it drops the connection
 * rather than queueing it. The fake Tally never did this, so nothing here predicted it.
 *
 * Retrying is safe because every request this transport makes is a READ — the TDL catalog
 * contains no mutation. A duplicated request costs one round trip and nothing else.
 *
 * ONE retry, not a loop: a reset that survives a pause is a real problem, and hammering a
 * desktop app the owner is typing into is exactly what this transport exists to avoid.
 */
const TRANSIENT_CODES = new Set(['ECONNRESET', 'ECONNABORTED', 'EPIPE']);

/** Long enough for Tally to finish whatever it was doing, short enough to feel instant. */
export const RETRY_PAUSE_MS = 300;

/**
 * Timeouts.
 *
 * Connect is 2s because this is localhost — Tally is either listening or it isn't; there is no
 * slow-network case to be generous about. Data timeouts are long because Tally is a
 * single-threaded desktop app that may be mid-export or blocked on a modal dialog the owner
 * left open.
 */
export const TIMEOUTS = {
  connectMs: 2_000,
  probeMs: 10_000,
  sectionMs: 60_000,
  /** First-run backfill pulls 12 months serially and is allowed to take longer. */
  backfillMs: 120_000,
} as const;

export type TallyFailure =
  /** Not an error. Tally is closed — the normal state overnight and every weekend. */
  | { kind: 'not_running' }
  /** Tally is up but no company is loaded. Also not an error; it's "waiting". */
  | { kind: 'no_company_open' }
  /** 200 OK, but the body isn't a Tally envelope. Something else owns :9000. */
  | { kind: 'not_tally'; bodyExcerpt: string }
  /** Tally answered with a fault (licence, security, bad TDL). */
  | { kind: 'tally_error'; message: string }
  | { kind: 'timeout'; afterMs: number }
  | { kind: 'http_status'; status: number }
  | { kind: 'network'; message: string };

export type TallyResult =
  | { ok: true; xml: string }
  | { ok: false; failure: TallyFailure };

export class TallyTransportError extends Error {
  // Written out rather than declared as a constructor parameter property: Node's
  // --experimental-strip-types is strip-only and cannot emit the assignment a parameter
  // property implies. Keeping the sources directly runnable is worth the extra line.
  readonly failure: TallyFailure;

  constructor(failure: TallyFailure) {
    super(describeFailure(failure));
    this.name = 'TallyTransportError';
    this.failure = failure;
  }
}

/**
 * Every failure gets a sentence a business owner could read.
 *
 * No stack trace, no error code, and no jargon ever reaches the UI — the UI shows this string
 * and an action button. That constraint is why this function exists next to the transport
 * rather than in the renderer: the person who adds a failure mode should have to write its
 * sentence at the same time.
 */
export function describeFailure(f: TallyFailure): string {
  switch (f.kind) {
    case 'not_running':
      return 'Tally is not open on this computer.';
    case 'no_company_open':
      return 'Tally is open, but no company is loaded.';
    case 'not_tally':
      return 'Another program is using port 9000, so we cannot reach Tally.';
    case 'tally_error':
      return `Tally reported a problem: ${f.message}`;
    case 'timeout':
      return 'Tally did not respond in time. It may be busy or waiting on a dialog box.';
    case 'http_status':
      return `Tally returned an unexpected response (HTTP ${f.status}).`;
    case 'network':
      return `Could not reach Tally: ${f.message}`;
  }
}

export interface TallyTransportOptions {
  host?: string;
  port?: number;
  /**
   * Request encoding. Omit to have the transport probe once and cache the winner —
   * see `TallyTransport.detectEncoding`.
   */
  encoding?: TallyEncoding;
}

/**
 * Talks to Tally's HTTP/XML server.
 *
 * STRICTLY ONE REQUEST AT A TIME. Tally's listener is embedded in a single-threaded desktop
 * app that the owner is actively typing into; concurrent requests cause hangs and, per field
 * reports, instability. Every call funnels through one mutex. There is no scenario where
 * parallelism is worth it here — the entire payload for a full sync is under 100KB.
 */
export class TallyTransport {
  private readonly host: string;
  private readonly port: number;
  private encoding: TallyEncoding | undefined;

  /** The mutex. Each request chains onto the previous one's settlement. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(opts: TallyTransportOptions = {}) {
    this.host = opts.host ?? '127.0.0.1';
    this.port = opts.port ?? DEFAULT_TALLY_PORT;
    this.encoding = opts.encoding;
  }

  get currentEncoding(): TallyEncoding | undefined {
    return this.encoding;
  }

  /** Serialize onto the single slot. */
  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    // Keep the chain alive regardless of outcome; a rejection must not poison the queue.
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async request(xml: string, timeoutMs: number = TIMEOUTS.sectionMs): Promise<TallyResult> {
    return this.enqueue(() => this.attempt(xml, this.encoding ?? 'utf16le', timeoutMs));
  }

  /**
   * One request, plus one retry if Tally dropped the connection.
   *
   * Runs INSIDE the mutex slot, so the retry cannot interleave with another request — the
   * one-request-at-a-time rule holds across the pause.
   */
  private async attempt(
    xml: string,
    encoding: TallyEncoding,
    timeoutMs: number,
  ): Promise<TallyResult> {
    const first = await this.rawRequest(xml, encoding, timeoutMs);
    if (!first.transient) return first;
    await new Promise((r) => setTimeout(r, RETRY_PAUSE_MS));
    return this.rawRequest(xml, encoding, timeoutMs);
  }

  /**
   * Determine which request encoding this Tally accepts, once, and cache it.
   *
   * Tries UTF-16LE first because that is what the one serious production implementation uses,
   * then falls back to UTF-8 which is what the official docs claim.
   */
  async detectEncoding(probeXml: string): Promise<TallyEncoding | undefined> {
    if (this.encoding) return this.encoding;

    for (const candidate of ['utf16le', 'utf8'] as const) {
      const res = await this.enqueue(() => this.attempt(probeXml, candidate, TIMEOUTS.probeMs));
      if (res.ok) {
        this.encoding = candidate;
        return candidate;
      }
      // Only an encoding-shaped failure justifies trying the other encoding. If Tally is
      // simply closed, retrying in UTF-8 tells us nothing and just doubles the wait.
      if (res.failure.kind === 'not_running' || res.failure.kind === 'not_tally') {
        return undefined;
      }
    }
    return undefined;
  }

  /**
   * `transient` is internal: it says "this failure is worth one retry", never leaves the
   * transport, and is deliberately absent from the public `TallyResult` so no caller can
   * grow a second retry policy on top of this one.
   */
  private rawRequest(
    xml: string,
    encoding: TallyEncoding,
    timeoutMs: number,
  ): Promise<TallyResult & { transient?: boolean }> {
    return new Promise((resolve) => {
      const body = encodeTallyRequest(xml, encoding);
      let settled = false;
      const done = (r: TallyResult & { transient?: boolean }) => {
        if (settled) return;
        settled = true;
        clearTimeout(overall);
        resolve(r);
      };

      const req = http.request(
        {
          host: this.host,
          port: this.port,
          method: 'POST',
          path: '/',
          headers: {
            'Content-Type': contentTypeFor(encoding),
            'Content-Length': body.length,
            // Do not pool. Tally's keep-alive handling is not worth trusting, and a pooled
            // socket into a desktop app that may be restarted at any moment is a liability.
            Connection: 'close',
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let received = 0;
          res.on('data', (c: Buffer) => {
            if (settled) return;
            received += c.length;
            if (received > MAX_RESPONSE_BYTES) {
              // Drop what we have and kill the socket NOW. Waiting for the overall deadline
              // would mean the memory is already gone by the time we notice, which defeats
              // the point of having a cap at all.
              chunks.length = 0;
              req.destroy();
              done({
                ok: false,
                failure: {
                  kind: 'not_tally',
                  bodyExcerpt: `Response exceeded ${MAX_RESPONSE_BYTES} bytes and was refused.`,
                },
              });
              return;
            }
            chunks.push(c);
          });
          res.on('end', () => {
            if (settled) return;
            const raw = Buffer.concat(chunks);

            if (res.statusCode && res.statusCode !== 200) {
              done({ ok: false, failure: { kind: 'http_status', status: res.statusCode } });
              return;
            }

            // An empty body means Tally is running but has no company loaded. This is a
            // verified behaviour and it is NOT an error — it's the state between the owner
            // launching Tally and opening their books.
            if (raw.length === 0) {
              done({ ok: false, failure: { kind: 'no_company_open' } });
              return;
            }

            const text = decodeTallyResponse(raw);

            if (!looksLikeTallyResponse(text)) {
              done({
                ok: false,
                failure: { kind: 'not_tally', bodyExcerpt: text.slice(0, 200) },
              });
              return;
            }

            const err = extractTallyError(text);
            if (err) {
              done({ ok: false, failure: { kind: 'tally_error', message: err } });
              return;
            }

            done({ ok: true, xml: text });
          });
        },
      );

      // Overall deadline, and the ONLY data-phase timer. Destroying the request is what frees
      // the socket, so a hung Tally cannot leak one — no separate idle-socket timer is needed,
      // and an idle timer shorter than this deadline would wrongly abort a slow-but-alive pull
      // (Tally goes silent for well over 30s while building a 12-month backfill).
      const overall = setTimeout(() => {
        req.destroy();
        done({ ok: false, failure: { kind: 'timeout', afterMs: timeoutMs } });
      }, timeoutMs);

      req.on('socket', (socket) => {
        // Connect timeout only applies until the socket is established.
        const connectTimer = setTimeout(() => {
          req.destroy();
          done({ ok: false, failure: { kind: 'timeout', afterMs: TIMEOUTS.connectMs } });
        }, TIMEOUTS.connectMs);
        const clear = () => clearTimeout(connectTimer);
        if (socket.connecting) socket.once('connect', clear);
        else clear();
        socket.once('close', clear);
      });

      req.on('error', (e: NodeJS.ErrnoException) => {
        if (e.code === 'ECONNREFUSED' || e.code === 'EHOSTUNREACH' || e.code === 'ENOTFOUND') {
          // Tally simply isn't open. Silent no-op for the caller, not a failure to surface.
          done({ ok: false, failure: { kind: 'not_running' } });
          return;
        }
        // A destroy() we initiated races with this handler; the timeout result already won.
        if (settled) return;
        done({
          ok: false,
          failure: { kind: 'network', message: e.message },
          transient: TRANSIENT_CODES.has(e.code ?? ''),
        });
      });

      req.end(body);
    });
  }
}
