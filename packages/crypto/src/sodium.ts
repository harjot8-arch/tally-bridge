import _sodium from 'libsodium-wrappers-sumo';

export type Sodium = typeof _sodium;

let cached: Sodium | undefined;

/**
 * libsodium compiles to wasm and initializes asynchronously. Every entry point in this
 * package awaits this. Callers should call it once at startup so the first real operation
 * isn't paying for initialization.
 */
export async function sodiumReady(): Promise<Sodium> {
  if (cached) return cached;
  await _sodium.ready;
  cached = _sodium;
  return cached;
}

/**
 * Zero a secret in place.
 *
 * This is best-effort and worth being honest about: it reliably clears the wasm heap, but
 * JS engines copy values freely and we cannot reach GC'd copies. It narrows the window a
 * heap dump would catch; it does not close it.
 */
export function wipe(sodium: Sodium, ...secrets: Uint8Array[]): void {
  for (const s of secrets) {
    try {
      sodium.memzero(s);
    } catch {
      // memzero rejects views it doesn't own; fall back to a manual overwrite.
      s.fill(0);
    }
  }
}

/** Constant-time comparison. Use for anything an attacker can submit repeatedly. */
export function timingSafeEqual(sodium: Sodium, a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return sodium.memcmp(a, b);
}
