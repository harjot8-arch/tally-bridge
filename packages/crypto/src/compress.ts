/**
 * Compression, via the WHATWG CompressionStream API.
 *
 * GZIP, NOT BROTLI — this is a deliberate correction to the original design.
 *
 * Brotli compresses this payload perhaps 10-15% better than gzip. But `DecompressionStream`
 * only standardized `br` in Chromium: Safari and Firefox cannot decode it natively, and this
 * dashboard is explicitly meant to be opened on a phone. The alternatives were a ~200KB wasm
 * brotli polyfill (on top of the ~200KB of libsodium wasm we already ship) or two separate
 * code paths (node:zlib on the Bridge, wasm in the browser) whose bugs would live exactly
 * where they're hardest to test.
 *
 * Gzip is native in Node 22 and in every browser through the same API, so the Bridge and the
 * dashboard run identical code. At 1-50KB the ratio difference is noise, and Padme padding
 * (see padme.ts) dominates the length-leak question anyway.
 *
 * The format is pinned as a protocol constant so that a change in compression ratio always
 * signals a change in DATA, never a change in client version.
 */

/** Pinned. Changing this is a wire-format break and requires an ENVELOPE_VERSION bump. */
export const COMPRESSION_FORMAT = 'gzip' as const;

/**
 * Hard ceiling on DECOMPRESSED output. The zip-bomb guard.
 *
 * The dashboard decompresses bytes that arrived from a server we explicitly do not trust, and
 * the AEAD does not save us here. Sealed boxes give confidentiality, not authenticity:
 * `crypto_box_seal` needs only the identity PUBLIC key and the server holds that key — it is
 * the key it hands to the Bridge. So the server can mint a fully valid envelope (fresh CEK
 * sealed to idPK, correct AAD, matching contentHash) around any plaintext it likes, and every
 * check in `openSection` passes. Decompression is therefore the first place attacker-chosen
 * data gets to choose its own size.
 *
 * Measured: 64MB of zeros gzips to 63.7KB — 1028:1, essentially gzip's theoretical maximum.
 * An 80KB forged ciphertext inflated to 60MB unchecked; a 10MB one reaches ~10GB. That is a
 * hard OOM on the phone this dashboard is explicitly meant to be opened on, from a blob that
 * costs the attacker nothing to store.
 *
 * 64MiB is ~1000x the largest real section (the architecture notes put them at 1-50KB), so it
 * can never be what breaks a legitimate customer, while staying inside what a mobile browser
 * can allocate without dying.
 */
export const MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;

async function runStream(
  data: Uint8Array,
  // CompressionStream's writable side accepts BufferSource, not Uint8Array specifically.
  stream: TransformStream<BufferSource, Uint8Array>,
  maxOutputBytes: number,
): Promise<Uint8Array> {
  const writer = stream.writable.getWriter();
  // Kick off the write without awaiting: the stream can deadlock if we drain only after
  // the write settles and the payload exceeds the internal buffer.
  const written = (async () => {
    // `Uint8Array` is generic over its backing buffer since TS 5.7, and BufferSource excludes
    // a SharedArrayBuffer backing. Nothing here is ever SAB-backed — every caller passes a
    // plain Uint8Array from TextEncoder, libsodium, or our own allocation.
    await writer.write(data as BufferSource);
    await writer.close();
  })();
  // Cancelling the readable below rejects that pending write. It is an expected consequence of
  // bailing out, not a fault, and must not surface as an unhandled rejection and kill the
  // process. `written` itself still rejects, so the `await written` on the success path below
  // continues to report genuine write failures.
  void written.catch(() => {});

  const chunks: Uint8Array[] = [];
  const reader = stream.readable.getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    // Per CHUNK, before retaining it. Checking the assembled total instead would mean the OOM
    // has already happened by the time we notice.
    if (total > maxOutputBytes) {
      await reader.cancel();
      throw new RangeError(
        `decompressed output exceeds ${maxOutputBytes} bytes — refusing to continue. ` +
          `This is a zip bomb or a corrupt blob; a real section is a few tens of KB.`,
      );
    }
    chunks.push(value);
  }
  await written;

  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export async function compress(data: Uint8Array): Promise<Uint8Array> {
  // No cap needed on this side: gzip output is bounded by its input plus a trivial header, and
  // the input is our own freshly-serialized payload, not attacker-chosen bytes.
  return runStream(data, new CompressionStream(COMPRESSION_FORMAT), Infinity);
}

export async function decompress(data: Uint8Array): Promise<Uint8Array> {
  return runStream(data, new DecompressionStream(COMPRESSION_FORMAT), MAX_DECOMPRESSED_BYTES);
}
