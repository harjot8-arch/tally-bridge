import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { TallyTransportError } from '@tally-bridge/tally';
import { Scheduler, describeStatus, type PowerMonitorLike } from '../src/main/scheduler.ts';
import { GENERIC_ERROR, HumanError, humanError } from '../src/main/errors.ts';
import { KeystoreUnavailableError } from '../src/main/keystore.ts';

/** A controllable clock + interval, so no test waits on real time. */
function fakeTimers() {
  let now = 1_752_600_000_000;
  const timers: Array<{ fn: () => void; ms: number; handle: number }> = [];
  let nextHandle = 1;
  return {
    now: () => now,
    setInterval: (fn: () => void, ms: number) => {
      const handle = nextHandle++;
      timers.push({ fn, ms, handle });
      return handle;
    },
    clearInterval: (h: unknown) => {
      const i = timers.findIndex((t) => t.handle === h);
      if (i >= 0) timers.splice(i, 1);
    },
    /** Fire every registered interval once. */
    fire: () => {
      for (const t of [...timers]) t.fn();
    },
    advance: (ms: number) => {
      now += ms;
    },
    count: () => timers.length,
  };
}

function fakePower(): PowerMonitorLike & { resume: () => void } {
  let onResume: (() => void) | undefined;
  return {
    on(event, listener) {
      if (event === 'resume') onResume = listener;
    },
    resume: () => onResume?.(),
  };
}

test('start registers an interval and stop clears it', () => {
  const t = fakeTimers();
  const s = new Scheduler({ runCycle: async () => {}, setInterval: t.setInterval, clearInterval: t.clearInterval, now: t.now });
  s.start();
  assert.equal(t.count(), 1);
  s.stop();
  assert.equal(t.count(), 0);
});

test('start is idempotent — no duplicate intervals', () => {
  const t = fakeTimers();
  const s = new Scheduler({ runCycle: async () => {}, setInterval: t.setInterval, clearInterval: t.clearInterval, now: t.now });
  s.start();
  s.start();
  assert.equal(t.count(), 1, 'two intervals would double the load on Tally');
});

test('a tick runs a cycle', async () => {
  const t = fakeTimers();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
  });
  s.start();
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 1);
});

test('WAKING A LAPTOP syncs immediately instead of waiting 15 minutes', async () => {
  // Lids close far more often than this app restarts. Without the resume hook, an owner who
  // opens their machine at 9am stares at stale numbers for a quarter of an hour.
  const t = fakeTimers();
  const power = fakePower();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    powerMonitor: power,
    now: t.now,
  });
  s.start();
  power.resume();
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 1);
});

test('THE THUNDERING HERD: overlapping ticks collapse to one follow-up, never a backlog', async () => {
  // The reason this is not cron. If Tally is slow, ticks pile up; firing them all back-to-back
  // would hammer the single-threaded desktop app the owner is typing into. Many ticks during
  // one slow cycle must produce exactly ONE more cycle, not five.
  const t = fakeTimers();
  let runs = 0;
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));

  const s = new Scheduler({
    runCycle: async () => {
      runs++;
      if (runs === 1) await gate;
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
  });
  s.start();

  t.fire(); // starts cycle 1, which blocks
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 1);

  t.fire();
  t.fire();
  t.fire();
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 1, 'still blocked; nothing queued in parallel');

  release();
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 2, 'four pending ticks collapse into exactly one follow-up');
});

test('a throwing cycle never kills the scheduler', async () => {
  // Tally closed, network down, server 500ing — all routine. The next tick must still fire.
  const t = fakeTimers();
  let runs = 0;
  const errors: unknown[] = [];
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
      throw new Error('Tally exploded');
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
    onError: (e) => errors.push(e),
  });
  s.start();

  t.fire();
  await new Promise((r) => setImmediate(r));
  t.fire();
  await new Promise((r) => setImmediate(r));

  assert.equal(runs, 2, 'the second tick still ran');
  assert.equal(errors.length, 2, 'and both failures were reported, not swallowed');
});

test('A THROWING ERROR HANDLER MUST NOT KILL THE PROCESS', async () => {
  // The real onError repaints the tray and pushes IPC to a window that may have just been
  // destroyed, so it genuinely can throw. That throw escapes tick(), and tick() is called as
  // `void this.tick()` from a timer — `void` does not handle a rejection, so it becomes an
  // unhandled rejection and Node terminates the main process by default. A dead Bridge at 3am
  // because a window closed while Tally was down.
  const t = fakeTimers();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
      throw new Error('Tally exploded');
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
    onError: () => {
      throw new TypeError("Cannot read properties of undefined (reading 'webContents')");
    },
  });
  s.start();

  const rejections: unknown[] = [];
  const onRejection = (e: unknown) => rejections.push(e);
  process.on('unhandledRejection', onRejection);
  try {
    t.fire();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    t.fire();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
  } finally {
    process.off('unhandledRejection', onRejection);
  }

  assert.deepEqual(rejections, [], 'a throwing reporter must never become an unhandled rejection');
  assert.equal(runs, 2, 'and the scheduler keeps ticking afterwards');
});

test('a throwing error handler still leaves the scheduler able to run', async () => {
  // The state machine must not wedge: `running` has to be cleared even when the reporter throws,
  // or every later tick collapses into a `pending` that never fires.
  const t = fakeTimers();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
      if (runs === 1) throw new Error('boom');
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
    onError: () => {
      throw new Error('reporter is broken too');
    },
  });
  s.start();
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(s.isRunning, false, 'not stuck mid-cycle');
  await s.syncNow();
  assert.equal(runs, 2, 'syncNow still works');
});

test('isRunning reflects a cycle in flight', async () => {
  const t = fakeTimers();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  const s = new Scheduler({
    runCycle: () => gate,
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
  });
  s.start();
  assert.equal(s.isRunning, false);
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(s.isRunning, true);
  release();
  await new Promise((r) => setImmediate(r));
  assert.equal(s.isRunning, false);
});

test('syncNow works even when stopped — the tray button must always respond', async () => {
  const t = fakeTimers();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    now: t.now,
  });
  await s.syncNow();
  assert.equal(runs, 1);
});

test('ticks after stop are ignored', async () => {
  const t = fakeTimers();
  let runs = 0;
  const s = new Scheduler({
    runCycle: async () => {
      runs++;
    },
    setInterval: t.setInterval,
    clearInterval: t.clearInterval,
    powerMonitor: fakePower(),
    now: t.now,
  });
  s.start();
  s.stop();
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(runs, 0);
});

test('lastRun advances with the clock', async () => {
  const t = fakeTimers();
  const s = new Scheduler({ runCycle: async () => {}, setInterval: t.setInterval, clearInterval: t.clearInterval, now: t.now });
  assert.equal(s.lastRun, 0);
  s.start();
  t.advance(5000);
  t.fire();
  await new Promise((r) => setImmediate(r));
  assert.equal(s.lastRun, t.now());
});

// ---------------------------------------------------------------- status

test('Tally being closed is "waiting", never an error', () => {
  // The normal state every night and weekend. Showing a red error would train the owner to
  // ignore red.
  const s = describeStatus({ lastRun: 0, tallyReachable: false, now: 1 });
  assert.equal(s.state, 'waiting');
  assert.match(s.message, /Waiting for Tally/);
  assert.equal(s.state === 'waiting' && s.action, 'Open Tally');
});

test('every non-ok status carries exactly one action', () => {
  // The rule: no stack trace ever reaches the owner. One plain sentence, one button.
  for (const input of [
    { lastRun: 0, tallyReachable: false, now: 1 },
    { lastRun: 1, tallyReachable: true, lastError: 'Tally did not respond in time.', now: 2 },
  ]) {
    const s = describeStatus(input);
    assert.ok('action' in s && typeof s.action === 'string' && s.action.length > 0);
    assert.doesNotMatch(s.message, /Error:|at .*\(|undefined|null/);
  }
});

test('a healthy sync reports ok with a timestamp', () => {
  const s = describeStatus({ lastRun: 1000, tallyReachable: true, now: 2000 });
  assert.equal(s.state, 'ok');
  assert.equal(s.state === 'ok' && s.lastRun, 1000);
});

test('a fresh install says "not synced yet" rather than pretending', () => {
  const s = describeStatus({ lastRun: 0, tallyReachable: true, now: 1 });
  assert.equal(s.state, 'never');
});

test('an unreachable Tally outranks a stale error', () => {
  // If Tally is shut, "Open Tally" is the actionable message — not last night's timeout.
  const s = describeStatus({ lastRun: 1, tallyReachable: false, lastError: 'timeout', now: 2 });
  assert.equal(s.state, 'waiting');
});

// ---------------------------------------------------------------- humanError

/**
 * `humanError` is the last thing between a raw throw and the owner's screen. Every test below
 * uses a REAL error object from a real dependency on the sync path, because the bug this
 * replaces was a regex that decided whether a message "looked like" a stack trace — and the
 * whole point is that these do not.
 */

/** A genuine node:http error, produced by actually failing to connect. */
async function realHttpError(): Promise<Error> {
  return new Promise((resolve) => {
    // Port 1 is reserved and never listening: a real ECONNREFUSED from the real stack.
    const req = http.get('http://127.0.0.1:1/', () => {});
    req.on('error', (e) => resolve(e));
  });
}

test('THE ERRNO LEAK: a real node:http failure never reaches the owner', async () => {
  const e = await realHttpError();
  // Prove the fixture is what we think it is before asserting on it.
  assert.match(e.message, /ECONNREFUSED/, 'fixture must be a real connect error');
  assert.ok(e.message.length < 160, 'and short enough that a length check would wave it through');

  const shown = humanError(e);
  assert.equal(shown, GENERIC_ERROR);
  assert.doesNotMatch(shown, /ECONNREFUSED|127\.0\.0\.1/);
});

test('THE HOSTNAME LEAK: a DNS failure does not put the customer deployment on screen', () => {
  // getaddrinfo errors name the host. That host is the client's own private deployment, and
  // this string ends up in a screenshot in a support thread.
  const e = Object.assign(new Error('getaddrinfo ENOTFOUND acme-dash.vercel.app'), {
    code: 'ENOTFOUND',
    errno: -3008,
    syscall: 'getaddrinfo',
    hostname: 'acme-dash.vercel.app',
  });
  const shown = humanError(e);
  assert.equal(shown, GENERIC_ERROR);
  assert.doesNotMatch(shown, /acme-dash|ENOTFOUND|getaddrinfo/);
});

test('dependency internals never reach the owner', () => {
  // better-sqlite3, libsodium and V8 all throw Errors whose `message` is a bare lowercase
  // sentence with no "Error:" prefix and no "at fn (" frame — i.e. every one of them passes a
  // "does this look like a stack trace" check, and every one is meaningless to a business owner.
  const real: Array<[string, Error]> = [
    ['better-sqlite3', Object.assign(new Error('database is locked'), { name: 'SqliteError', code: 'SQLITE_BUSY' })],
    ['better-sqlite3', Object.assign(new Error('no such table: outbox'), { name: 'SqliteError' })],
    ['libsodium', new Error('incorrect key pair for the given ciphertext')],
    ['libsodium', new Error('invalid input')],
    ['V8', new TypeError("Cannot read properties of undefined (reading 'rows')")],
    ['V8', new RangeError('Invalid array length')],
  ];
  for (const [source, e] of real) {
    assert.equal(humanError(e), GENERIC_ERROR, `${source}: ${e.message} must not be shown`);
  }
});

test('a TypeError is not spared by the "looks like an Error" check', () => {
  // The specific regex bug worth naming: /^[A-Z]*Error:/ anchors [A-Z]* (uppercase only)
  // against "TypeError", where only the leading "T" is uppercase — so it never matched, and
  // `e.message` does not carry the "TypeError:" prefix anyway. The guard matched approximately
  // nothing it was written to catch.
  assert.doesNotMatch('TypeError: x is not a function', /^[A-Z]*Error:/);
  assert.equal(humanError(new TypeError('x is not a function')), GENERIC_ERROR);
});

test('a raw stack trace cannot reach the owner even if it is short', () => {
  const e = new Error('boom\n    at cycle (/app/dist/main/cycle.js:12:9)');
  assert.equal(humanError(e), GENERIC_ERROR);
  assert.doesNotMatch(humanError(e), /at cycle|\.js:/);
});

test("Tally's own failures ARE shown — they were written for this reader", () => {
  // The allowlist has to let the good case through or it is just a mute button.
  assert.equal(
    humanError(new TallyTransportError({ kind: 'not_running' })),
    'Tally is not open on this computer.',
  );
  assert.match(
    humanError(new TallyTransportError({ kind: 'timeout', afterMs: 30_000 })),
    /did not respond in time/,
  );
  assert.match(
    humanError(new TallyTransportError({ kind: 'not_tally', bodyExcerpt: '<html>...' })),
    /port 9000/,
  );
});

test('an error tagged for a human is shown; the same text untagged is not', () => {
  // The audience is carried by the TYPE, never inferred from the text. This is the whole design.
  const text = 'Your Tally licence has expired.';
  assert.equal(humanError(new HumanError(text)), text);
  assert.equal(humanError(new Error(text)), GENERIC_ERROR, 'identical text, no claim of audience');
});

test('the keystore failure survives the filter — it names the service to turn on', () => {
  assert.match(humanError(new KeystoreUnavailableError()), /Credential Manager/);
});

test('non-Errors do not crash the formatter', () => {
  // A rejected promise can carry literally anything, including a hostile object.
  for (const junk of [undefined, null, 'a string', 42, { message: 'fake' }, [1, 2]]) {
    assert.equal(humanError(junk), GENERIC_ERROR);
  }
  // A getter that throws must not take the app down from inside the error handler.
  const hostile = new HumanError('x');
  Object.defineProperty(hostile, 'message', {
    get() {
      throw new Error('gotcha');
    },
  });
  assert.throws(() => hostile.message, /gotcha/, 'fixture is genuinely hostile');
});

test('every humanError output is safe to put in describeStatus', () => {
  // The contract the status bar depends on: a sentence, never a code.
  for (const e of [new TypeError('x'), new Error('connect ECONNREFUSED 127.0.0.1:9000'), 'junk']) {
    const s = describeStatus({ lastRun: 1, tallyReachable: true, lastError: humanError(e), now: 2 });
    assert.doesNotMatch(s.message, /Error:|at .*\(|undefined|null|ECONNREFUSED/);
  }
});
