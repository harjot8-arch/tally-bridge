import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_DECOMPRESSED_BYTES, compress, decompress } from '../src/compress.ts';

test('compress/decompress round-trips', async () => {
  const data = new TextEncoder().encode(JSON.stringify({ debtors: 'x'.repeat(5000) }));
  assert.deepEqual(await decompress(await compress(data)), data);
});

test('compress/decompress round-trips an empty payload', async () => {
  const empty = new Uint8Array(0);
  assert.deepEqual(await decompress(await compress(empty)), empty);
});

test('decompress rejects a corrupt stream', async () => {
  await assert.rejects(() => decompress(new Uint8Array([1, 2, 3, 4, 5])));
});

/**
 * Adversarial: the zip bomb.
 *
 * The dashboard decompresses data that came from a server we do not trust. Worse, sealed boxes
 * give confidentiality but NOT authenticity: `crypto_box_seal` needs only the identity PUBLIC
 * key, and the server holds that key — it hands it to the Bridge. So the server can mint a
 * fully valid envelope (fresh CEK sealed to idPK, correct AAD, matching contentHash) whose
 * plaintext is a bomb, and every integrity check in `openSection` passes.
 *
 * Measured before the cap: 64MB of zeros gzips to 63.7KB (1028:1, near gzip's theoretical max),
 * and an 80KB forged ciphertext inflated to 60MB in `openSection` with nothing to stop it. At
 * that ratio a 10MB blob is 10GB — a hard OOM on the phone this is meant to be opened on.
 */
test('decompress refuses a zip bomb rather than OOMing the dashboard', async () => {
  // Well under the cap in ciphertext, far over it once inflated.
  const bomb = await compress(new Uint8Array(MAX_DECOMPRESSED_BYTES + 1024 * 1024));
  assert.ok(
    bomb.length < 1024 * 1024,
    `bomb should be small on the wire, was ${bomb.length} bytes`,
  );
  await assert.rejects(() => decompress(bomb), /exceeds|zip bomb/i);
});

test('the cap aborts mid-stream, not after allocating the whole bomb', async () => {
  // The check must run per chunk. If it only ran on the assembled output, the OOM would have
  // already happened by the time we threw.
  const bomb = await compress(new Uint8Array(MAX_DECOMPRESSED_BYTES * 4));
  const before = process.memoryUsage().heapUsed;
  await assert.rejects(() => decompress(bomb), /exceeds|zip bomb/i);
  const grew = process.memoryUsage().heapUsed - before;
  // Generous: the point is that it is bounded by the cap, not by 4x the cap.
  assert.ok(
    grew < MAX_DECOMPRESSED_BYTES * 2,
    `heap grew ${(grew / 1024 / 1024).toFixed(0)}MB decompressing a bomb 4x the cap`,
  );
});

test('a payload just under the cap still decompresses', async () => {
  // The cap must not break legitimate data. Real sections are 1-50KB; this is far beyond that
  // but must still work, so the cap is never the thing that breaks a real customer.
  const big = new Uint8Array(1024 * 1024).fill(65);
  assert.equal((await decompress(await compress(big))).length, big.length);
});

test('the cap leaves multiple orders of magnitude of headroom over a real section', async () => {
  // Sections are 1-50KB per the architecture notes. If the cap were ever tightened to near
  // that, a large book would break in production; if raised to gigabytes, the bomb is back.
  assert.ok(MAX_DECOMPRESSED_BYTES >= 16 * 1024 * 1024);
  assert.ok(MAX_DECOMPRESSED_BYTES <= 128 * 1024 * 1024);
});
