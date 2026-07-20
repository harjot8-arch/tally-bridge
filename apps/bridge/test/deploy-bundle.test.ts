import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROUTES } from '@tally-bridge/protocol';
import { loadDeployBundle } from '../src/main/wizard-effects.ts';
import { HumanError } from '../src/main/errors.ts';
import { VercelClient, provision, type DeployFile, type ProvisionEvent } from '../src/onboarding/vercel.ts';

/**
 * The deploy pipeline, end to end on this side of the Vercel API:
 *
 *   build script -> Build Output API v3 directory -> loadDeployBundle -> VercelClient.deploy
 *
 * The bundle is built ONCE (it runs esbuild plus two spawned verification processes — the
 * health smoke and the bundled-libsodium probe — so a failure in either fails `before`, which
 * is itself an assertion: a bundle that cannot pass its own smoke must not build).
 *
 * Mutations run against these tests (each applied, observed red, reverted):
 *   - drop `?prebuilt=1` from deploy()                    -> prebuilt test red
 *   - stop writing schema.sql into the .func dirs         -> shape test red
 *   - stop writing config.json                            -> loadDeployBundle honesty test red
 *     (and the shape test)
 *   - upload every file instead of unique shas            -> dedupe test red
 *   - break the entry's default export                    -> `before` fails via the smoke
 */

const REPO_ROOT = join(import.meta.dirname, '../../..');
let bundleDir: string;

before(() => {
  bundleDir = mkdtempSync(join(tmpdir(), 'tb-deploy-bundle-'));
  execFileSync(
    process.execPath,
    ['--experimental-strip-types', join(REPO_ROOT, 'scripts/build-deploy-bundle.ts'), '--out', bundleDir],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
});

after(() => {
  rmSync(bundleDir, { recursive: true, force: true });
});

/* ------------------------------------------------------------------ bundle shape */

test('the bundle is Build Output API v3 with one function per route path', () => {
  const config = JSON.parse(readFileSync(join(bundleDir, '.vercel/output/config.json'), 'utf8')) as {
    version: number;
  };
  assert.equal(config.version, 3);

  for (const route of Object.values(ROUTES)) {
    const func = join(bundleDir, `.vercel/output/functions${route.path}.func`);
    assert.ok(existsSync(func), `${route.path} has no .func directory — the route would 404 in production`);

    const vc = JSON.parse(readFileSync(join(func, '.vc-config.json'), 'utf8')) as Record<string, unknown>;
    assert.equal(vc['handler'], 'index.js');
    assert.equal(vc['launcherType'], 'Nodejs');
    // Helpers parse the JSON body; the upload signature covers the raw bytes. True here would
    // 401 every honest upload.
    assert.equal(vc['shouldAddHelpers'], false);
    assert.match(String(vc['runtime']), /^nodejs\d+\.x$/);

    const bundle = readFileSync(join(func, 'index.js'));
    assert.ok(bundle.byteLength > 100_000, `${route.path} bundle is implausibly small — not self-contained`);

    // The lazy migrator reads schema.sql from beside index.js; without it every function's
    // first request dies on a missing relation.
    const schema = readFileSync(join(func, 'schema.sql'), 'utf8');
    assert.match(schema, /CREATE TABLE/i);

    // Pins CJS regardless of any parent package.json's "type": "module".
    const pkg = JSON.parse(readFileSync(join(func, 'package.json'), 'utf8')) as { type?: string };
    assert.equal(pkg.type, 'commonjs');
  }
});

/* ------------------------------------------------------------------ loadDeployBundle */

test('loadDeployBundle keeps the .vercel/output/ prefix on the wire and hashes correctly', () => {
  const files = loadDeployBundle(bundleDir);
  assert.ok(files.length > 0);
  assert.ok(files.every((f) => f.file.startsWith('.vercel/output/')), 'a path lost its prefix');
  assert.ok(files.some((f) => f.file === '.vercel/output/config.json'));

  const config = files.find((f) => f.file === '.vercel/output/config.json')!;
  assert.equal(config.sha, createHash('sha1').update(config.data).digest('hex'));
  assert.equal(config.size, config.data.byteLength);
});

test('loadDeployBundle refuses a directory that is not a deployable bundle', () => {
  // Missing entirely.
  assert.throws(() => loadDeployBundle(join(tmpdir(), 'tb-does-not-exist')), HumanError);

  // Present but hollow: files exist, none of them the function or the config. Deploying this
  // would "succeed" into a dashboard serving nothing — the exact green-tick failure to refuse.
  const hollow = mkdtempSync(join(tmpdir(), 'tb-hollow-'));
  try {
    mkdirSync(join(hollow, '.vercel/output'), { recursive: true });
    writeFileSync(join(hollow, '.vercel/output/stray.txt'), 'not a bundle');
    assert.throws(() => loadDeployBundle(hollow), HumanError);
  } finally {
    rmSync(hollow, { recursive: true, force: true });
  }
});

/* ------------------------------------------------------------------ VercelClient.deploy */

function fakeUpload() {
  const deployCalls: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fileUploads: string[] = [];

  const fetchImpl: typeof globalThis.fetch = async (input, init) => {
    const url = String(input);
    const method = init?.method ?? 'GET';
    const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });

    if (url.includes('/v2/files')) {
      const headers = init?.headers as Record<string, string>;
      fileUploads.push(headers['x-vercel-digest'] ?? '?');
      return json({});
    }
    if (url.includes('/v13/deployments') && method === 'POST') {
      deployCalls.push({ url, body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      return json({ id: 'dpl_1', url: 'x.vercel.app' });
    }
    if (url.includes('/v13/deployments/dpl_1')) return json({ readyState: 'READY', url: 'x.vercel.app' });
    if (url.includes('/v2/user')) return json({ user: { username: 'u' } });
    if (url.includes('/v1/integrations/configurations')) return json([{ id: 'icfg_1', slug: 'neon' }]);
    if (url.includes('/v11/projects')) return json({ id: 'prj_1', name: 'p' });
    if (url.includes('/v1/storage/stores/integration/direct')) return json({ store: { id: 'st_1' } });
    if (url.includes('/v1/storage/stores/st_1')) return json({ store: { status: 'available' } });
    if (url.includes('/connections')) return json({});
    if (url.includes('/env')) return json({});
    return new Response('{}', { status: 404 });
  };

  return { fetchImpl, deployCalls, fileUploads };
}

const df = (file: string, data: string): DeployFile => {
  const bytes = new TextEncoder().encode(data);
  return { file, sha: createHash('sha1').update(bytes).digest('hex'), size: bytes.byteLength, data: bytes };
};

test('deploy() sends ?prebuilt=1 — the CLI-verified signal that no build must run', async () => {
  const fake = fakeUpload();
  const client = new VercelClient({
    token: 't',
    fetch: fake.fetchImpl,
    sleep: async () => {},
    now: () => 0,
  });
  await client.deploy('proj', [df('.vercel/output/config.json', '{"version":3}')]);

  assert.equal(fake.deployCalls.length, 1);
  const call = fake.deployCalls[0]!;
  const params = new URL(call.url).searchParams;
  assert.equal(params.get('prebuilt'), '1', 'the prebuilt flag is missing; Vercel would try to BUILD the output');
  // A prebuilt bundle is not a framework build.
  assert.equal((call.body['projectSettings'] as { framework: unknown }).framework, null);
  // Paths must keep their prefix on the wire.
  const files = call.body['files'] as Array<{ file: string }>;
  assert.ok(files.every((f) => f.file.startsWith('.vercel/output/')));
});

test('provision() uploads each distinct sha once, not once per route copy', async () => {
  const fake = fakeUpload();
  const client = new VercelClient({
    token: 't',
    fetch: fake.fetchImpl,
    sleep: async () => {},
    now: () => 0,
  });

  const sharedBundle = 'const s = "identical function bytes";';
  const files = [
    df('.vercel/output/config.json', '{"version":3}'),
    df('.vercel/output/functions/api/sync.func/index.js', sharedBundle),
    df('.vercel/output/functions/api/health.func/index.js', sharedBundle),
    df('.vercel/output/functions/api/devices.func/index.js', sharedBundle),
  ];

  const events: ProvisionEvent[] = [];
  await provision(
    client,
    {
      projectName: 'p',
      tenantId: 'tn_1',
      identityPublicKey: 'pk',
      bootstrapSecret: 's',
      schemaVersion: '1',
      files,
    },
    { pollMs: 1, installTimeoutMs: 1000, dbTimeoutMs: 1000, deployTimeoutMs: 1000 },
    (e) => events.push(e),
  );

  // 4 files, 2 distinct shas (three .func copies share one), so exactly 2 uploads…
  assert.equal(fake.fileUploads.length, 2, `uploaded ${fake.fileUploads.length} blobs for 2 distinct shas`);
  // …while the deployment manifest still names all 4 paths.
  const manifest = fake.deployCalls[0]!.body['files'] as Array<{ file: string }>;
  assert.equal(manifest.length, 4);
});

/**
 * THE DASHBOARD DATA LAYER MUST ACTUALLY SHIP.
 *
 * `apps/web` is a library with no production caller by design — the owner writes the UI that
 * calls it. That is exactly the shape this repo has been burned by four times: fully built,
 * fully tested, and unreachable. The caller here is the DEPLOY BUNDLE, and this is the test that
 * fails if it stops carrying the data layer.
 *
 * Without these two files served beside index.html, the owner's dashboard has nothing to import
 * and no amount of passing unit tests in apps/web would reveal it.
 */
test('the deploy bundle SHIPS the dashboard data layer beside index.html', () => {
  const staticDir = join(bundleDir, '.vercel/output/static');

  // Each file carries a DIFFERENT contract, and asserting one API against both is how this test
  // first went red: `tally-worker.js` is the worker entry and correctly has no `loadDashboard`.
  const expected = {
    // The public API the README tells a UI author to call. If this ships without them, the
    // handoff document is lying.
    'tally-data.js': ['unlock', 'loadDashboard', 'lockSession'],
    // The worker's whole job: the two Argon2id operations, off the main thread.
    'tally-worker.js': ['deriveAuthTokenInline', 'openPassIdentityInline'],
  };

  for (const [asset, names] of Object.entries(expected)) {
    const p = join(staticDir, asset);
    assert.ok(existsSync(p), `${asset} is not in the deploy bundle — the UI would have nothing to import`);
    const src = readFileSync(p, 'utf8');
    assert.ok(src.length > 100_000, `${asset} is suspiciously small (${src.length}B) — did the build emit a stub?`);
    for (const name of names) {
      assert.ok(src.includes(name), `${asset} does not contain ${name}`);
    }
  }
});

/**
 * SECURITY HEADERS ON THE PUBLIC DASHBOARD.
 *
 * This deployment is a public page on the client's own domain that takes the owner's PASSPHRASE
 * and renders their decrypted finances. It shipped with NO headers at all, while two comments in
 * this repo asserted a CSP was already protecting things — both false, both corrected.
 *
 * `frame-ancestors 'none'` is the one that matters most: without it the passphrase field is
 * frameable, which is clickjacking. `script-src 'self'` is what makes a CDN script tag (the
 * owner's original UI had one) fail closed rather than execute.
 */
test('the deployment sets a real CSP and the clickjacking/sniffing headers', () => {
  const config = JSON.parse(
    readFileSync(join(bundleDir, '.vercel/output/config.json'), 'utf8'),
  ) as { routes: Array<{ headers?: Record<string, string>; handle?: string; continue?: boolean }> };

  const headerRoute = config.routes.find((r) => r.headers !== undefined);
  assert.ok(headerRoute, 'no route carries security headers — the dashboard ships unprotected');
  const h = headerRoute.headers!;

  const csp = h['Content-Security-Policy'] ?? '';
  assert.match(csp, /script-src 'self'/, 'script-src must forbid third-party scripts');
  assert.match(csp, /frame-ancestors 'none'/, 'a passphrase page must not be frameable');
  assert.match(csp, /connect-src 'self'/, 'the dashboard must only talk to its own API');
  assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), "script-src must NOT allow 'unsafe-inline'");

  assert.equal(h['X-Content-Type-Options'], 'nosniff');
  assert.equal(h['X-Frame-Options'], 'DENY');
  assert.ok((h['Strict-Transport-Security'] ?? '').includes('max-age='));

  // The header rule must not swallow routing — the filesystem phase still has to serve files.
  assert.equal(headerRoute.continue, true, 'headers must not terminate routing');
  assert.ok(
    config.routes.some((r) => r.handle === 'filesystem'),
    'the filesystem phase must still be present or nothing is served',
  );
});
