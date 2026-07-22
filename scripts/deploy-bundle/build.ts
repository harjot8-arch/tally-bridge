import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { ALL_ROUTES } from '../../packages/protocol/src/routes.ts';

/**
 * The deploy-bundle build pipeline.
 *
 * Produces a Vercel BUILD OUTPUT API v3 directory that `loadDeployBundle()` (apps/bridge)
 * reads and `VercelClient.deploy()` pushes with `?prebuilt=1`. No Next.js, no build step on
 * Vercel's side: what this writes is byte-for-byte what runs in the client's account.
 *
 * ## Shape
 *
 *   <out>/.vercel/output/config.json                     {"version":3, routes}
 *   <out>/.vercel/output/static/index.html               one honest sentence at "/"
 *   <out>/.vercel/output/functions/api/<route>.func/     one function PER ROUTE PATH:
 *       .vc-config.json                                  nodejs runtime config
 *       index.js                                         the self-contained server bundle
 *       schema.sql                                       read by the lazy migrator at runtime
 *
 * ## Why one function per route path, not one catch-all behind a rewrite
 *
 * A catch-all needs a `routes` rewrite (`/api/(.*)` -> `/api`), and whether the function then
 * sees the ORIGINAL url or the REWRITTEN one in `req.url` is exactly the thing we cannot
 * verify without a real deployment — and the signed path sits inside the Ed25519 signature, so
 * guessing wrong is a silent 401 on the owner's own deployment (see routes.ts). Filesystem
 * matching has no rewrite: `functions/api/sync.func` serves `/api/sync` and the function's
 * `req.url` is the path the client requested. The cost is N copies of the same bundle on disk;
 * Vercel's upload is content-addressed by sha, so the bytes go over the wire ONCE (and
 * `provision()` dedupes the upload calls by sha).
 *
 * Two routes share a path (GET and PUT /api/wrapped-keys); they share one .func directory and
 * the in-function router dispatches on method.
 *
 * ## Why the function must be self-contained
 *
 * `?prebuilt=1` deploys run NO install step: whatever is inside the .func directory is the
 * entire filesystem the function gets. So everything — @tally-bridge/*, libsodium,
 * @neondatabase/serverless — is bundled into one index.js by esbuild (a BUILD-TIME dependency
 * only; nothing new ships at runtime).
 *
 * libsodium: MEASURED, not assumed. The 0.8.x builds embed the wasm as base64 inside the JS
 * (no external .wasm file, no fetch), so bundling cannot orphan it — and this pipeline still
 * proves it every run: `verifyBundledSodium` bundles a sign/verify probe with the same esbuild
 * options and executes it. A libsodium upgrade that switches to external wasm files fails the
 * build here, not at runtime in the client's cloud.
 *
 * ## CJS + import.meta.url
 *
 * Output is CommonJS (the launcher's safest module format), but migrate.ts locates schema.sql
 * via `import.meta.url` — meaningless in CJS. The banner/define pair below rebuilds it from
 * `__filename`, so `new URL('./schema.sql', import.meta.url)` resolves next to index.js, which
 * is exactly where this pipeline copies schema.sql. The build fails if schema.sql is missing
 * or empty rather than shipping a function that 500s its first migration.
 *
 * ## What is UNVERIFIABLE without a real Vercel token (kept as guesses, not claims)
 *
 *   - `runtime: "nodejs20.x"` is the value from Vercel's published Build Output API examples;
 *     newer runtimes exist but cannot be probed from here.
 *   - The launcher invoking `module.exports.default` when the CJS module has a `default`
 *     export. vercel/vercel's node launcher does interop on `mod.default`, but the server side
 *     is closed. The experiment that settles both: deploy this bundle with a real token and
 *     hit /api/health.
 */

export interface BuildOptions {
  /** Where the bundle root goes. The directory is replaced. */
  outDir: string;
  /** Skip the spawned-process verification steps (smoke + sodium probe). Tests use the default. */
  verify?: boolean;
}

export interface BuildResult {
  outDir: string;
  /** POSIX-relative paths of every file written, `.vercel/output/...` prefix included. */
  files: string[];
  functionPaths: string[];
}

const REPO_ROOT = join(import.meta.dirname, '../..');

/**
 * Runtime config for each function. `shouldAddHelpers: false` is load-bearing: the helpers
 * parse JSON bodies, and the upload signature covers the raw bytes — see entry.ts.
 */
const VC_CONFIG = {
  runtime: 'nodejs20.x',
  handler: 'index.js',
  launcherType: 'Nodejs',
  shouldAddHelpers: false,
};

export async function buildDeployBundle(opts: BuildOptions): Promise<BuildResult> {
  const { build } = await import('esbuild');
  const out = opts.outDir;
  const output = join(out, '.vercel/output');

  const esbuildOptions = {
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    // Bundle the workspace packages from SOURCE, not from dist: a stale dist here would deploy
    // last week's route table into the client's cloud with today's Bridge signing against it.
    alias: {
      '@tally-bridge/core': join(REPO_ROOT, 'packages/core/src/index.ts'),
      '@tally-bridge/crypto': join(REPO_ROOT, 'packages/crypto/src/index.ts'),
      '@tally-bridge/protocol': join(REPO_ROOT, 'packages/protocol/src/index.ts'),
    },
    // The CJS import.meta.url shim described in the header comment.
    banner: { js: `const __tb_import_meta_url = require('node:url').pathToFileURL(__filename).href;` },
    define: { 'import.meta.url': '__tb_import_meta_url' },
    write: false as const,
    logLevel: 'silent' as const,
  } satisfies Parameters<typeof build>[0];

  const bundled = await build({
    ...esbuildOptions,
    entryPoints: [join(REPO_ROOT, 'apps/server/src/entry.ts')],
    outfile: 'index.js',
  });
  const indexJs = bundled.outputFiles?.[0]?.contents;
  if (!indexJs || indexJs.byteLength === 0) {
    throw new Error('esbuild produced no output for the server entry');
  }

  const schemaSql = readFileSync(join(REPO_ROOT, 'apps/server/src/schema.sql'), 'utf8');
  // The migrator's lazy first-request migration is the ONLY thing that creates tables; a bundle
  // whose schema.sql is missing or hollow deploys "successfully" into a server whose first
  // request dies on a missing relation. Refuse to build it.
  if (!/CREATE TABLE/i.test(schemaSql)) {
    throw new Error('apps/server/src/schema.sql has no CREATE TABLE statements; refusing to bundle it');
  }

  rmSync(out, { recursive: true, force: true });
  const files: string[] = [];
  const write = (rel: string, data: Uint8Array | string) => {
    const abs = join(output, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, data);
    files.push(`.vercel/output/${rel}`);
  };

  /*
   * SECURITY HEADERS. Previously this config carried NONE, while two comments in this repo
   * claimed a CSP was already enforcing things — both false, and corrected.
   *
   * This deployment is a PUBLIC page on the client's own domain that takes the owner's
   * PASSPHRASE and renders their decrypted finances. Without headers it was framable
   * (clickjacking a passphrase field) and would happily execute a CDN script.
   *
   * Applied with `continue: true` so the header rule does not terminate routing — the
   * `handle: 'filesystem'` phase below still runs and serves the static files and functions.
   *
   * `style-src` allows 'unsafe-inline' ONLY because the owner's dashboard is a single
   * self-contained page with a <style> block; script-src does NOT, so an injected <script>
   * cannot execute. If the UI ever moves its CSS to a file, drop 'unsafe-inline' here too.
   * `connect-src 'self'` is what confines the dashboard's fetches to its own API.
   */
  const SECURITY_HEADERS = {
    'Content-Security-Policy': [
      "default-src 'self'",
      // 'wasm-unsafe-eval' is REQUIRED, not optional: the dashboard runs Argon2id via libsodium's
      // WebAssembly inside the unlock Web Worker, and browsers gate WebAssembly.instantiate() behind
      // script-src. Bare 'self' makes the wasm refuse to compile, the worker throws on the first
      // derive, and the whole sign-in dies with an opaque error — on every browser, phone included.
      // This token allows wasm compilation WITHOUT allowing eval() (unlike 'unsafe-eval').
      "script-src 'self' 'wasm-unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "object-src 'none'",
    ].join('; '),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  };

  write(
    'config.json',
    JSON.stringify(
      {
        version: 3,
        routes: [
          { src: '/(.*)', headers: SECURITY_HEADERS, continue: true },
          { handle: 'filesystem' },
        ],
      },
      null,
      2,
    ),
  );

  /*
   * The dashboard — data layer AND the owner's UI — ships as static assets.
   *
   * `apps/web` builds two browser ES modules (see apps/web/build.mjs). They are the "backend for
   * the UI": unlock, fetch, decrypt, card view models — the part the owner must not have to
   * write. The owner's UI (index.html/app.js/viewmap.js, from apps/web/ui via apps/web/dist)
   * now ships beside it; the placeholder index.html below is only the fallback for a dist
   * that predates the UI.
   *
   * We BUILD it here rather than hoping someone already did. `apps/web/dist` is gitignored, so
   * on a fresh clone "did you remember to run build.mjs" is a step that will eventually be
   * missed — and the failure is silent: a deployment that serves the API and no dashboard, with
   * nothing but a console.warn on a machine nobody is watching. Building is deterministic and
   * takes ~1s, so there is no reason to leave it to memory.
   *
   * A build FAILURE is still only a warning, for the original reason: the API half of this
   * deployment is complete and useful without a dashboard, and failing the whole deploy over a
   * UI asset would block the Bridge from ever syncing.
   */
  const webDist = join(REPO_ROOT, 'apps/web/dist');
  try {
    runNode([join(REPO_ROOT, 'apps/web/build.mjs')], 'apps/web build failed');
  } catch (e) {
    console.warn(`deploy bundle: ${(e as Error).message}`);
  }
  let shippedDataLayer = false;
  let shippedUi = false;
  // index.html/app.js/viewmap.js are the owner's dashboard UI (apps/web/ui, copied into dist
  // by apps/web/build.mjs). NEVER ship apps/web/ui/index.original.html — it is the design
  // reference and still contains the Math.random() simulation and the cdnjs GSAP tag.
  for (const asset of ['tally-data.js', 'tally-worker.js', 'index.html', 'app.js', 'viewmap.js']) {
    const from = join(webDist, asset);
    if (!existsSync(from)) continue;
    write(`static/${asset}`, readFileSync(from));
    if (asset === 'tally-data.js' || asset === 'tally-worker.js') shippedDataLayer = true;
    if (asset === 'index.html') shippedUi = true;
  }
  if (!shippedDataLayer) {
    console.warn(
      'deploy bundle: apps/web/dist is missing — shipping the API without the dashboard data ' +
        'layer. Run `node build.mjs` in apps/web to include it.',
    );
  }

  if (!shippedUi) {
    write(
      'static/index.html',
      [
        '<!doctype html>',
        '<html lang="en"><head><meta charset="utf-8"><title>Tally Bridge</title></head>',
        '<body><p>This deployment hosts the Tally Bridge sync API for its owner. There is nothing to see here.</p></body></html>',
        '',
      ].join('\n'),
    );
  }

  // One .func per unique PATH; ALL_ROUTES may list several methods on one path.
  const functionPaths = [...new Set(ALL_ROUTES.map((r) => r.path))];
  for (const path of functionPaths) {
    const dir = `functions${path}.func`;
    write(`${dir}/.vc-config.json`, JSON.stringify(VC_CONFIG, null, 2));
    write(`${dir}/index.js`, indexJs);
    // Pin the module format. Node decides CJS-vs-ESM from the NEAREST package.json, and what
    // that is depends on where the .func directory happens to sit — locally it inherits
    // apps/bridge's `"type": "module"` and the CJS bundle dies on require(); in the lambda it
    // depends on Vercel's filesystem layout, which we cannot inspect. One two-key file makes
    // the answer the same everywhere. (Measured: the health smoke fails without this.)
    write(`${dir}/package.json`, JSON.stringify({ type: 'commonjs' }));
    write(`${dir}/schema.sql`, schemaSql);
  }

  if (opts.verify !== false) {
    smokeTestBundledFunction(join(output, 'functions/api/health.func'));
    await verifyBundledSodium(esbuildOptions);
  }

  return { outDir: out, files, functionPaths };
}

/**
 * Execute the REAL bundle from the output directory, exactly as written, and demand a 200 from
 * /api/health. This is what catches a bundling failure (an unresolved require, a broken shim, a
 * launcher-shape mistake in entry.ts) at build time on our machine instead of at cold start in
 * the client's account.
 */
function smokeTestBundledFunction(funcDir: string): void {
  runNode([join(import.meta.dirname, 'smoke.cjs'), funcDir], 'the bundled function failed its health smoke test');
}

/**
 * Bundle a libsodium sign/verify round trip with the SAME options as the server bundle and run
 * it. Passing means the embedded wasm initialises and Ed25519 works inside an esbuild CJS
 * bundle on this Node — the exact configuration the deployed function uses.
 */
async function verifyBundledSodium(esbuildOptions: object): Promise<void> {
  const { build } = await import('esbuild');
  const probe = await build({
    ...esbuildOptions,
    entryPoints: [join(import.meta.dirname, 'sodium-probe.ts')],
    outfile: 'probe.js',
  } as Parameters<typeof build>[0]);
  const contents = probe.outputFiles?.[0]?.contents;
  if (!contents) throw new Error('esbuild produced no output for the sodium probe');

  const dir = join(tmpdir(), `tb-sodium-probe-${process.pid}-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, 'probe.cjs');
  try {
    writeFileSync(file, contents);
    runNode([file], 'libsodium did not survive bundling: the sign/verify probe failed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runNode(args: string[], failure: string): void {
  try {
    execFileSync(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    const stderr = (e as { stderr?: Buffer }).stderr?.toString() ?? '';
    throw new Error(`${failure}\n${stderr}`.trim());
  }
}
