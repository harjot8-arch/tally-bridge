import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  VercelClient,
  VercelError,
  provision,
  safeProjectName,
  type ProvisionEvent,
} from '../src/onboarding/vercel.ts';

/**
 * A fake Vercel.
 *
 * The real API cannot be scripted into its interesting states on demand — you cannot ask it to
 * hold a database at `initializing`, or to 402 you, or to pretend Neon is not installed yet.
 * Those are exactly the states that decide whether onboarding works for a non-technical owner,
 * so they are tested here against a stand-in.
 *
 * This does NOT replace Spike B, which answers a different question: whether an OAuth token is
 * permitted to create projects at all. No fake can answer that.
 */
interface FakeOpts {
  neonInstalledAfterPolls?: number;
  dbReadyAfterPolls?: number;
  deployReadyAfterPolls?: number;
  failWith?: { path: RegExp; status: number };
  hasTeam?: boolean;
}

function fakeVercel(opts: FakeOpts = {}) {
  let neonPolls = 0;
  let dbPolls = 0;
  let deployPolls = 0;
  const calls: string[] = [];
  const envSet: Array<{ key: string; type: string }> = [];
  let connectedBeforeReady = false;
  let dbReady = false;

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = String(input);
    const path = url.replace('https://api.vercel.com', '');
    const method = init?.method ?? 'GET';
    calls.push(`${method} ${path.split('?')[0]}`);

    if (opts.failWith && opts.failWith.path.test(path)) {
      return new Response('{"error":{"message":"nope"}}', { status: opts.failWith.status });
    }

    const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });

    if (path.startsWith('/v2/user')) return json({ user: { username: 'ramesh' } });
    if (path.startsWith('/v2/teams')) {
      return json({ teams: opts.hasTeam ? [{ id: 'team_1', name: 'Acme' }] : [] });
    }

    if (path.startsWith('/v1/integrations/configurations')) {
      neonPolls++;
      const ready = neonPolls > (opts.neonInstalledAfterPolls ?? 0);
      return json(ready ? [{ id: 'icfg_neon1', slug: 'neon' }] : []);
    }

    if (path.startsWith('/v11/projects')) return json({ id: 'prj_1', name: 'acme-dash' });

    if (path.startsWith('/v1/storage/stores/integration/direct')) {
      return json({ store: { id: 'store_1', status: 'initializing' } });
    }

    if (path.startsWith('/v1/storage/stores/store_1')) {
      dbPolls++;
      dbReady = dbPolls > (opts.dbReadyAfterPolls ?? 0);
      return json({ store: { id: 'store_1', status: dbReady ? 'available' : 'initializing' } });
    }

    if (path.includes('/resources/store_1/connections')) {
      // Record the ordering violation rather than throwing: the assertion belongs in the test.
      if (!dbReady) connectedBeforeReady = true;
      return json({});
    }

    if (path.includes('/env')) {
      const body = JSON.parse(String(init?.body ?? '[]')) as Array<{ key: string; type: string }>;
      envSet.push(...body);
      return json({});
    }

    if (path.startsWith('/v2/files')) return json({});

    if (path.startsWith('/v13/deployments/')) {
      deployPolls++;
      const ready = deployPolls > (opts.deployReadyAfterPolls ?? 0);
      return json({ readyState: ready ? 'READY' : 'BUILDING', url: 'acme-dash.vercel.app' });
    }
    if (path.startsWith('/v13/deployments')) return json({ id: 'dpl_1', url: 'acme-dash.vercel.app' });

    return new Response('{}', { status: 404 });
  };

  return {
    fetch,
    calls,
    envSet,
    get connectedBeforeReady() {
      return connectedBeforeReady;
    },
  };
}

function client(fake: ReturnType<typeof fakeVercel>, teamId?: string) {
  const events: ProvisionEvent[] = [];
  let clock = 0;
  const c = new VercelClient({
    token: 'tok_1',
    teamId,
    fetch: fake.fetch,
    // No test waits on real time; advancing the clock here is what makes timeouts testable.
    sleep: async (ms) => {
      clock += ms;
    },
    now: () => clock,
    log: (e) => events.push(e),
  });
  return { c, events, advance: (ms: number) => (clock += ms) };
}

const TIMINGS = { pollMs: 1000, installTimeoutMs: 300_000, dbTimeoutMs: 120_000, deployTimeoutMs: 300_000 };

const FILES = [{ file: 'index.js', sha: 'abc', size: 3, data: new Uint8Array([1, 2, 3]) }];

const INPUT = {
  projectName: 'acme-dash',
  tenantId: 'tnt_1',
  identityPublicKey: 'cHVibGlj',
  bootstrapSecret: 'super-secret',
  schemaVersion: '1',
  files: FILES,
};

test('the happy path provisions end to end', async () => {
  const fake = fakeVercel();
  const { c } = client(fake);
  const events: ProvisionEvent[] = [];
  const res = await provision(c, INPUT, TIMINGS, (e) => events.push(e));

  assert.equal(res.projectId, 'prj_1');
  assert.equal(res.deploymentUrl, 'acme-dash.vercel.app');
  const steps = events.filter((e) => e.kind === 'step').map((e) => (e as { step: string }).step);
  assert.deepEqual(steps, [
    'verify_token', 'check_neon', 'create_project', 'provision_database',
    'connect_database', 'set_env', 'upload_files', 'deploy', 'await_ready', 'done',
  ]);
});

test('THE ORDERING RULE: the database is never connected before it is available', async () => {
  // Connecting against `initializing` yields a deployment that boots into a crash loop — which
  // looks exactly like our bug and burns a day of support before anyone suspects the database.
  const fake = fakeVercel({ dbReadyAfterPolls: 3 });
  const { c } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});
  assert.equal(fake.connectedBeforeReady, false);
});

test('`available` is the only status accepted as ready', async () => {
  const fake = fakeVercel({ dbReadyAfterPolls: 2 });
  const { c } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});
  // It polled rather than trusting the first `initializing` response.
  assert.ok(fake.calls.filter((x) => x.includes('/v1/storage/stores/store_1')).length >= 3);
});

test('THE ONE MANUAL CLICK is guided, not dumped on the user', async () => {
  // The step we cannot automate. The app opens the page, says what to do, and watches — the
  // owner never has to navigate back or tell us they are finished.
  const fake = fakeVercel({ neonInstalledAfterPolls: 3 });
  const { c, events } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});

  const prompt = events.find((e) => e.kind === 'needs_human');
  assert.ok(prompt, 'must tell the user exactly what to do');
  assert.equal(prompt.kind === 'needs_human' && prompt.url, 'https://vercel.com/marketplace/neon');
  assert.match(prompt.kind === 'needs_human' ? prompt.message : '', /click "install"/i);
  assert.ok(events.some((e) => e.kind === 'waiting'), 'and then wait for them');
});

test('an already-installed Neon skips the manual step entirely', async () => {
  const fake = fakeVercel({ neonInstalledAfterPolls: 0 });
  const { c, events } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});
  assert.ok(!events.some((e) => e.kind === 'needs_human'), 'a second install must be frictionless');
});

test('waiting forever is not a plan: the install poll times out with an action', async () => {
  const fake = fakeVercel({ neonInstalledAfterPolls: 99_999 });
  const { c } = client(fake);
  await assert.rejects(
    () => provision(c, INPUT, { ...TIMINGS, installTimeoutMs: 5_000 }, () => {}),
    (e: VercelError) => {
      assert.equal(e.userActionable, true);
      assert.match(e.message, /Install/);
      return true;
    },
  );
});

test('BOOTSTRAP_SECRET is set as sensitive, and before the deploy', async () => {
  // Because this app provisions the server, it can mint the secret the server will expect —
  // provisioning and trust-bootstrap become the same step, with no out-of-band channel.
  const fake = fakeVercel();
  const { c } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});

  const secret = fake.envSet.find((v) => v.key === 'BOOTSTRAP_SECRET');
  assert.ok(secret, 'must be set');
  assert.equal(secret.type, 'sensitive', 'must never be a plain env var');

  const envIdx = fake.calls.findIndex((x) => x.includes('/env'));
  const deployIdx = fake.calls.findIndex((x) => x === 'POST /v13/deployments');
  assert.ok(envIdx < deployIdx, 'the server must boot already knowing the secret');
});

test('the identity public key is shipped, and no secret ever is', async () => {
  const fake = fakeVercel();
  const { c } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});
  const keys = fake.envSet.map((v) => v.key);
  assert.ok(keys.includes('IDENTITY_PUBKEY'));
  assert.ok(!keys.some((k) => /SECRET_KEY|PRIVATE|PASSPHRASE/i.test(k)));
});

test('the deploy uses inline files — NO GitHub account required', async () => {
  // The Deploy Button path would force a GitHub signup on a non-technical business owner and
  // leave the dashboard source in a repo they can accidentally delete.
  const fake = fakeVercel();
  const { c } = client(fake);
  await provision(c, INPUT, TIMINGS, () => {});
  assert.ok(fake.calls.includes('POST /v2/files'), 'files are uploaded directly');
  assert.ok(!fake.calls.some((x) => /git|repo/i.test(x)), 'no git provider is ever contacted');
});

test('402 reads as "add a card", not as a status code', async () => {
  // A growing SMB WILL outgrow Neon's free tier. This is the difference between a support call
  // that resolves in one sentence and one that does not.
  const fake = fakeVercel({ failWith: { path: /\/v1\/storage\/stores\/integration\/direct/, status: 402 } });
  const { c } = client(fake);
  await assert.rejects(
    () => provision(c, INPUT, TIMINGS, () => {}),
    (e: VercelError) => {
      assert.match(e.message, /payment method/i);
      assert.equal(e.userActionable, true);
      assert.doesNotMatch(e.message, /402|error|\{/);
      return true;
    },
  );
});

test('a bad token tells the user to paste a fresh one', async () => {
  const fake = fakeVercel({ failWith: { path: /\/v2\/user/, status: 401 } });
  const { c } = client(fake);
  await assert.rejects(
    () => provision(c, INPUT, TIMINGS, () => {}),
    (e: VercelError) => {
      assert.match(e.message, /token/i);
      assert.equal(e.userActionable, true);
      return true;
    },
  );
});

test('a duplicate project name is actionable, not fatal-looking', async () => {
  const fake = fakeVercel({ failWith: { path: /\/v11\/projects/, status: 409 } });
  const { c } = client(fake);
  await assert.rejects(
    () => provision(c, INPUT, TIMINGS, () => {}),
    (e: VercelError) => {
      assert.match(e.message, /already exists/);
      return true;
    },
  );
});

test('a Vercel outage is not blamed on the user', async () => {
  const fake = fakeVercel({ failWith: { path: /\/v11\/projects/, status: 503 } });
  const { c } = client(fake);
  await assert.rejects(
    () => provision(c, INPUT, TIMINGS, () => {}),
    (e: VercelError) => {
      assert.match(e.message, /Vercel is having trouble/);
      assert.equal(e.userActionable, false, 'nothing for the owner to do but wait');
      return true;
    },
  );
});

test('no error message ever leaks a raw API body', async () => {
  // The owner must never see JSON. Every status maps to a sentence.
  for (const status of [400, 401, 402, 403, 409, 429, 500, 503]) {
    const fake = fakeVercel({ failWith: { path: /\/v2\/user/, status } });
    const { c } = client(fake);
    await assert.rejects(
      () => provision(c, INPUT, TIMINGS, () => {}),
      (e: VercelError) => {
        assert.doesNotMatch(e.message, /\{|\}|"error"|nope/, `status ${status} leaked a body`);
        return true;
      },
    );
  }
});

test('a build failure is reported rather than hung on', async () => {
  const fake = fakeVercel();
  const orig = fake.fetch;
  const failing: typeof globalThis.fetch = async (i, init) => {
    if (String(i).includes('/v13/deployments/')) {
      return new Response(JSON.stringify({ readyState: 'ERROR' }), { status: 200 });
    }
    return orig(i, init);
  };
  const { c } = client({ ...fake, fetch: failing });
  await assert.rejects(() => provision(c, INPUT, TIMINGS, () => {}), /failed to build/);
});

test('a personal account with no team still works', async () => {
  // Most of this market will never create a Vercel team.
  const fake = fakeVercel({ hasTeam: false });
  const { c } = client(fake);
  assert.equal(await c.resolveTeam(), undefined);
  await provision(c, INPUT, TIMINGS, () => {});
});

test('teamId is threaded through every call when one exists', async () => {
  const fake = fakeVercel({ hasTeam: true });
  const withTeam = new VercelClient({
    token: 't', teamId: 'team_1', fetch: fake.fetch, sleep: async () => {}, now: () => 0,
  });
  const urls: string[] = [];
  const spy: typeof globalThis.fetch = async (i, init) => {
    urls.push(String(i));
    return fake.fetch(i, init);
  };
  const c2 = new VercelClient({ token: 't', teamId: 'team_1', fetch: spy, sleep: async () => {}, now: () => 0 });
  await c2.createProject('x');
  assert.ok(urls[0]!.includes('teamId=team_1'));
  void withTeam;
});

// ---------------------------------------------------------------- naming

test('project names are slugged safely', () => {
  assert.match(safeProjectName('Acme Traders Pvt Ltd', 'a1b2'), /^acme-traders-pvt-ltd-dash-a1b2$/);
  assert.match(safeProjectName('M/s Sharma & Sons!', 'x'), /^m-s-sharma-sons-dash-x$/);
});

test('a business named entirely in Devanagari still gets a valid project name', () => {
  // Extremely likely in this market, and it would otherwise slug to empty and produce a
  // baffling 400 from Vercel at the worst moment of onboarding.
  const name = safeProjectName('देवनागरी व्यापारी', 'x7');
  assert.equal(name, 'tally-dash-x7');
  assert.match(name, /^[a-z0-9-]+$/);
});

test('very long business names are truncated to a legal length', () => {
  const name = safeProjectName('A'.repeat(200), 'x');
  assert.ok(name.length <= 100);
  assert.match(name, /^[a-z0-9-]+$/);
});

test('leading and trailing punctuation does not produce a stray hyphen', () => {
  // Vercel rejects names starting or ending with a hyphen.
  assert.equal(safeProjectName('---Acme---', 'x'), 'acme-dash-x');
  assert.equal(safeProjectName('!!!', 'x'), 'tally-dash-x');
});

// ---------------------------------------------------------------- ADVERSARIAL: project names

/**
 * Vercel's rule: 1-100 chars, lowercase, alphanumeric plus `.` `_` `-`, and it will not accept
 * a name that starts or ends with a hyphen or contains `---`.
 */
function projectNameProblems(n: string): string[] {
  const bad: string[] = [];
  if (n.length === 0) bad.push('empty');
  if (n.length > 100) bad.push(`too long (${n.length})`);
  if (!/^[a-z0-9._-]*$/.test(n)) bad.push('illegal characters');
  if (/^[-.]|[-.]$/.test(n)) bad.push('leading/trailing hyphen or dot');
  if (n.includes('---')) bad.push('triple hyphen');
  return bad;
}

test('safeProjectName survives a fuzz of real-world business names', () => {
  const suffixes = ['', 'a1', 'A1B2', 'x'.repeat(80), '-', '--', '..', '🎉', 'Z'.repeat(200)];
  const names = [
    'Acme Traders',
    '',
    '   ',
    'श्री गणेश ट्रेडर्स', // Devanagari: slugs to empty
    '🎉🎉🎉',
    '‮evil‬', // RTL override
    '-'.repeat(50) + 'a',
    'a'.repeat(39) + ' b', // the slice lands exactly on a hyphen
    'A'.repeat(500),
    'Ramesh & Co. (Pvt) Ltd.',
    'Café Münchën',
    'x'.repeat(39) + '-' + 'y'.repeat(39),
  ];
  const failures: string[] = [];
  for (const n of names) {
    for (const s of suffixes) {
      const out = safeProjectName(n, s);
      const problems = projectNameProblems(out);
      if (problems.length) failures.push(`${JSON.stringify(n.slice(0, 20))}+${JSON.stringify(s.slice(0, 10))} -> ${JSON.stringify(out)}: ${problems.join(', ')}`);
    }
  }
  assert.deepEqual(failures, [], `safeProjectName produced names Vercel will reject:\n${failures.join('\n')}`);
});

test('safeProjectName still produces a recognisable name', () => {
  assert.equal(safeProjectName('Acme Traders', 'a1b2'), 'acme-traders-dash-a1b2');
  assert.match(safeProjectName('श्री गणेश', 'a1'), /^tally-dash-a1$/, 'a non-Latin name still gets a usable slug');
});

// ---------------------------------------------------------------- ADVERSARIAL: the PAT

test('THE TOKEN NEVER APPEARS IN AN ERROR, WHATEVER VERCEL ECHOES BACK', async () => {
  // Vercel echoing the Authorization header back in an error body is not hypothetical — plenty
  // of APIs do it on a 400. If any of that reaches the message, the token lands in a screenshot
  // attached to a support ticket.
  const TOKEN = 'tok_SUPER_SECRET_PAT_VALUE';
  const fetch: typeof globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { message: `bad token ${TOKEN}`, headers: { authorization: `Bearer ${TOKEN}` } } }), { status: 400 });
  const c = new VercelClient({ token: TOKEN, fetch, sleep: async () => {}, now: () => 0 });

  for (const attempt of [
    () => c.verifyToken(),
    () => c.createProject('x'),
    () => c.provisionNeon('icfg_1', 'db'),
    () => c.findNeonConfiguration(),
    () => c.setEnv('prj', [{ key: 'K', value: 'V' }]),
    () => c.deploy('x', []),
    () => c.uploadFile({ file: 'a', sha: 'b', size: 1, data: new Uint8Array([1]) }),
  ]) {
    const e = await attempt().then(() => undefined, (err: unknown) => err);
    assert.ok(e instanceof Error, 'must throw');
    const dump = `${e.message} ${e.stack ?? ''} ${JSON.stringify(e, Object.getOwnPropertyNames(e))}`;
    assert.ok(!dump.includes(TOKEN), `the PAT leaked: ${e.message}`);
  }
});

// ---------------------------------------------------------------- ADVERSARIAL: the retry

/** A fake that behaves like a real account: a name can only be created once. */
function statefulVercel() {
  const projects = new Map<string, string>();
  let deployAttempts = 0;
  const opts = { failDeploys: 0 };
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const path = String(input).replace('https://api.vercel.com', '').split('?')[0]!;
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });

    if (path.startsWith('/v2/user')) return json({ user: { username: 'ramesh' } });
    if (path.startsWith('/v1/integrations/configurations')) return json([{ id: 'icfg_neon1', slug: 'neon' }]);
    if (path === '/v11/projects') {
      const name = JSON.parse(String(init?.body)).name as string;
      if (projects.has(name)) return json({ error: { message: 'name exists' } }, 409);
      projects.set(name, `prj_${projects.size + 1}`);
      return json({ id: projects.get(name), name });
    }
    if (path.startsWith('/v9/projects/')) {
      const name = decodeURIComponent(path.slice('/v9/projects/'.length));
      const id = projects.get(name);
      return id ? json({ id, name }) : json({ error: { message: 'not found' } }, 404);
    }
    if (path.startsWith('/v1/storage/stores/integration/direct')) return json({ store: { id: 'store_1' } });
    if (path.startsWith('/v1/storage/stores/')) return json({ store: { id: 'store_1', status: 'available' } });
    if (path.includes('/connections')) return json({});
    if (path.includes('/env')) return json({});
    if (path.startsWith('/v2/files')) return json({});
    if (path.startsWith('/v13/deployments/')) return json({ readyState: 'READY', url: 'acme-dash.vercel.app' });
    if (path.startsWith('/v13/deployments')) {
      if (deployAttempts++ < opts.failDeploys) throw new TypeError('fetch failed');
      return json({ id: 'dpl_1', url: 'acme-dash.vercel.app' });
    }
    return json({}, 404);
  };
  return { fetch, opts, projects };
}

test('RETRY AFTER THE WIFI DROPS MID-SETUP: provisioning resumes instead of 409ing forever', async () => {
  // THE failure this module has to survive. `createProject` succeeded, then the owner's
  // connection died before `deploy`. The project name is derived deterministically from the
  // business name, so every retry re-POSTs the same name and gets 409 — permanently. Worse, the
  // wizard maps 409 to a `choose_another_name` action, and the owner has no way to know that
  // their half-built project is the thing blocking them.
  const fake = statefulVercel();
  fake.opts.failDeploys = 1;

  const mk = () =>
    new VercelClient({ token: 'tok_1', fetch: fake.fetch, sleep: async () => {}, now: () => 0 });

  await assert.rejects(() => provision(mk(), INPUT, TIMINGS, () => {}), 'attempt 1 dies at the deploy');
  assert.equal(fake.projects.size, 1, 'the project really was created before the failure');

  // The owner clicks "Try again".
  const r = await provision(mk(), INPUT, TIMINGS, () => {});
  assert.equal(r.deploymentUrl, 'acme-dash.vercel.app');
  assert.equal(fake.projects.size, 1, 'the retry reuses the existing project rather than duplicating it');
});

test('a genuine name collision with someone else’s project is still reported', async () => {
  // The 409 path must not become a silent "reuse whatever is there" for a project we cannot see:
  // if the lookup does not find it, the owner still needs the honest message.
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = String(input).replace('https://api.vercel.com', '').split('?')[0]!;
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
    if (path.startsWith('/v2/user')) return json({ user: { username: 'r' } });
    if (path.startsWith('/v1/integrations/configurations')) return json([{ id: 'icfg_neon1', slug: 'neon' }]);
    if (path === '/v11/projects') return json({ error: { message: 'exists' } }, 409);
    if (path.startsWith('/v9/projects/')) return json({ error: { message: 'not found' } }, 404);
    return json({}, 404);
  };
  const c = new VercelClient({ token: 't', fetch, sleep: async () => {}, now: () => 0 });
  const e = await provision(c, INPUT, TIMINGS, () => {}).then(() => undefined, (x: unknown) => x);
  assert.ok(e instanceof VercelError);
  assert.equal(e.status, 409);
  assert.match(e.message, /already exists/);
});

test('a token revoked mid-poll aborts promptly and blames the token, not Neon', async () => {
  // awaitNeonInstall polls until timeout. If the owner revokes/rotates the PAT while the Neon
  // page is open, every poll 401s. It must stop at once with "paste a new token" — not keep
  // polling for five minutes and then say "we did not see Neon installed", which sends the
  // owner to re-click Install on a page where nothing is wrong.
  let polls = 0;
  const fetch: typeof globalThis.fetch = async (input) => {
    const path = String(input).replace('https://api.vercel.com', '');
    if (path.startsWith('/v1/integrations/configurations')) {
      polls++;
      return polls === 1
        ? new Response('[]', { status: 200 })
        : new Response('{"error":{"message":"invalid token"}}', { status: 401 });
    }
    return new Response('{}', { status: 200 });
  };
  let clock = 0;
  const c = new VercelClient({
    token: 'tok_1', fetch, sleep: async (ms) => { clock += ms; }, now: () => clock,
  });
  const e = await c
    .awaitNeonInstall({ timeoutMs: 300_000, pollMs: 1000 })
    .then(() => undefined, (x: unknown) => x);

  assert.ok(e instanceof VercelError);
  assert.equal(e.status, 401, 'the 401 must surface, not be swallowed by the poll loop');
  assert.ok(clock < 300_000, 'it must not burn the whole timeout');
  assert.match(e.message, /token/i);
});
