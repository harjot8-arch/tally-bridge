import { ROUTES, signRequest, verifyRequest, type VerifyDeps } from '@tally-bridge/protocol';
import { sodiumReady } from '@tally-bridge/crypto';

/**
 * The libsodium-in-a-bundle probe. Bundled by build.ts with the SAME esbuild options as the
 * server function, then executed. Exit 0 means: the embedded wasm initialised, Ed25519
 * sign/verify round-trips, and a tampered body is refused — all inside a CJS esbuild bundle on
 * the Node this machine runs. That is the strongest statement about "does libsodium survive
 * bundling" available without deploying.
 *
 * No top-level await: the bundle target is CommonJS.
 */
async function main(): Promise<void> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_sign_keypair();
  const body = new TextEncoder().encode('{"probe":true}');

  const headers = await signRequest(
    { deviceId: 'dev_probe', method: ROUTES.sync.method, path: ROUTES.sync.path, body },
    kp.privateKey,
  );

  const deps: VerifyDeps = {
    lookupDevice: async () => ({ publicKey: kp.publicKey, revoked: false }),
    rememberNonce: async () => true,
    admit: async () => ({ ok: true }),
    now: () => Date.now(),
  };

  const good = await verifyRequest(
    headers,
    { method: ROUTES.sync.method, path: ROUTES.sync.path, body },
    deps,
  );
  if (!good.ok) {
    throw new Error(`bundled verify refused an honest signature: ${JSON.stringify(good)}`);
  }

  // The negative control, so a probe that "passes" by never really verifying is caught.
  const tampered = await verifyRequest(
    headers,
    { method: ROUTES.sync.method, path: ROUTES.sync.path, body: new TextEncoder().encode('{"probe":false}') },
    deps,
  );
  if (tampered.ok) {
    throw new Error('bundled verify accepted a tampered body — the probe itself is broken');
  }
}

main().then(
  () => {
    console.log('SODIUM_OK');
    process.exit(0);
  },
  (e) => {
    console.error(e);
    process.exit(1);
  },
);
