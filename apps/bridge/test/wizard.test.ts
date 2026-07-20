import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeRecoverySheet, type RecoverySheet } from '../src/onboarding/recovery.ts';
import { VercelError } from '../src/onboarding/vercel.ts';
import {
  MIN_PASSPHRASE_LENGTH,
  actionOf,
  checkPassphrase,
  initialState,
  isComplete,
  isProblem,
  messageOf,
  next,
  phaseOf,
  type TallyCompany,
  type WizardEvent,
  type WizardState,
} from '../src/onboarding/wizard.ts';

/**
 * The wizard is a pure function, so these tests are the real thing rather than a stand-in for
 * it: there is no Electron, no socket, and no key here that the production code would have and
 * these tests would not. Every property that matters about onboarding — the recovery gate, the
 * ordering of identity-before-provisioning, the absence of stack traces — is decidable from
 * `next()` alone, which is why `next()` is where they live.
 */

const ACME: TallyCompany = { guid: 'guid-acme', name: 'Acme Traders' };
const BETA: TallyCompany = { guid: 'guid-beta', name: 'Beta Exports' };
const PASS = 'ledger book monday';

/**
 * A sheet whose 24 words are DISTINCT.
 *
 * `new Uint8Array(32).fill(seed)` — what this used to be — is 32 identical bytes, and BIP39 packs
 * 11 bits per word, so the entropy repeats on an 8-word cycle: word #17 IS word #1 and word #4 IS
 * word #12. Every "a word from the WRONG POSITION must be rejected" assertion built on it was
 * vacuously true — it was rejecting a word that was also the right answer. An adversarial pass
 * found its own first attack draft was a silent no-op against this fixture.
 *
 * Counting bytes makes all 24 words distinct, so a position test tests position.
 */
function sheetFor(seed = 7): RecoverySheet {
  const entropy = Uint8Array.from({ length: 32 }, (_, i) => (seed + i * 31) & 0xff);
  const sheet = makeRecoverySheet(entropy, 'Acme Traders', '2026-07-16');
  assert.equal(new Set(sheet.words).size, sheet.words.length, 'fixture must have 24 distinct words');
  return sheet;
}

function drive(events: WizardEvent[], from: WizardState = initialState()): WizardState {
  return events.reduce(next, from);
}

/** findTally -> connectCloud, one company, identity generated. */
function atAwaitToken(): WizardState {
  return drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    { type: 'identity_ready', identityPublicKey: 'PK_BASE64' },
  ]);
}

function atProvisioning(): WizardState {
  return drive([{ type: 'token_pasted', token: 'vercel_pat_xxx' }], atAwaitToken());
}

/** On the recovery-sheet screen, holding a known sheet — one `continue` short of the gate. */
function atSheet(sheet: RecoverySheet = sheetFor()): WizardState {
  return drive(
    [
      { type: 'provision_succeeded', projectId: 'prj_1', deploymentUrl: 'https://acme.vercel.app' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'sheet_ready', sheet },
    ],
    atProvisioning(),
  );
}

/** All the way to the verification gate, holding a known sheet. */
function atVerify(sheet: RecoverySheet = sheetFor()): WizardState {
  return drive(
    [
      { type: 'provision_succeeded', projectId: 'prj_1', deploymentUrl: 'https://acme.vercel.app' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'sheet_ready', sheet },
      { type: 'continue' },
    ],
    atProvisioning(),
  );
}

// ---------------------------------------------------------------- screen 1: find Tally

test('the wizard opens by probing for Tally rather than asking the owner anything', () => {
  assert.deepEqual(initialState(), { screen: 'findTally', phase: 'probing' });
});

test('TALLY CLOSED IS NOT AN ERROR: one plain sentence, one "Try again", no error code', () => {
  // Tally is closed every night and every weekend. Rendering that as an error is how you
  // train an owner to ignore errors, which costs you the one time an error is real.
  const s = next(initialState(), { type: 'probe_failed', failure: { kind: 'not_running' } });

  assert.equal(s.screen, 'findTally');
  assert.equal(phaseOf(s), 'waiting');
  assert.equal(isProblem(s), false);

  const message = messageOf(s)!;
  assert.equal(message, 'Tally is not open on this computer.');
  // Exactly one sentence.
  assert.match(message, /^[^.]+\.$/);
  // No error code, status, or port number can hide in a string with no digits in it.
  assert.equal(/\d/.test(message), false);

  const action = actionOf(s)!;
  assert.equal(action.label, 'Try again');
  assert.equal(action.kind, 'retry_probe');
});

test('"no company loaded" is also a wait, not a failure', () => {
  const s = next(initialState(), { type: 'probe_failed', failure: { kind: 'no_company_open' } });
  assert.equal(phaseOf(s), 'waiting');
  assert.equal(isProblem(s), false);
  assert.equal(actionOf(s)!.label, 'Try again');
});

test('Tally answering with zero companies reads as waiting, because to the owner it is', () => {
  const s = next(initialState(), { type: 'probe_succeeded', companies: [] });
  assert.equal(phaseOf(s), 'waiting');
  assert.equal(isProblem(s), false);
});

test('"Try again" from a wait re-probes', () => {
  const waiting = next(initialState(), { type: 'probe_failed', failure: { kind: 'not_running' } });
  assert.deepEqual(next(waiting, { type: 'retry' }), { screen: 'findTally', phase: 'probing' });
});

test('a real Tally problem IS a problem, but still carries one sentence and one action', () => {
  const s = next(initialState(), { type: 'probe_failed', failure: { kind: 'timeout', afterMs: 10_000 } });
  assert.equal(isProblem(s), true);
  assert.equal(actionOf(s)!.label, 'Try again');
});

test('a transport-level failure never leaks the status code to the owner', () => {
  // describeFailure() in the transport says "(HTTP 502)". That is right for its reader and
  // wrong for this one: a status code on the first setup screen tells a business owner only
  // that this software is not for them.
  const s = next(initialState(), { type: 'probe_failed', failure: { kind: 'http_status', status: 502 } });
  assert.equal(/502|HTTP/.test(messageOf(s)!), false);
});

test("Tally's own fault text is passed through, but sanitised — it is arbitrary XML content", () => {
  // This is text we do not control, parsed out of a response body. Raw interpolation is how
  // the one screen that promised no jargon ends up showing <LINEERROR> to a business owner.
  const s = next(initialState(), {
    type: 'probe_failed',
    failure: { kind: 'tally_error', message: '<LINEERROR>Licence\n  not  active</LINEERROR>' },
  });
  assert.equal(messageOf(s), 'Tally reported a problem: Licence not active.');

  // A fault that is already a sentence is not given a second full stop.
  const t = next(initialState(), {
    type: 'probe_failed',
    failure: { kind: 'tally_error', message: 'Company is locked by another user.' },
  });
  assert.equal(messageOf(t), 'Tally reported a problem: Company is locked by another user.');

  // A paragraph is clipped rather than allowed to blow out the banner.
  const long = next(initialState(), {
    type: 'probe_failed',
    failure: { kind: 'tally_error', message: 'x'.repeat(500) },
  });
  assert.ok(messageOf(long)!.length < 160);

  // An empty fault still yields a sentence rather than a dangling colon.
  const empty = next(initialState(), { type: 'probe_failed', failure: { kind: 'tally_error', message: '   ' } });
  assert.equal(messageOf(empty), 'Tally reported a problem: no details were given.');
});

test('one company is pre-selected, so the owner is not asked a question with one answer', () => {
  const s = next(initialState(), { type: 'probe_succeeded', companies: [ACME] });
  assert.equal(phaseOf(s), 'ready');
  assert.equal(s.screen === 'findTally' && s.phase === 'ready' ? s.selectedGuid : undefined, ACME.guid);
});

test('several companies force an explicit choice: Continue does nothing until one is picked', () => {
  const listed = next(initialState(), { type: 'probe_succeeded', companies: [ACME, BETA] });
  assert.equal(listed.screen === 'findTally' && listed.phase === 'ready' ? listed.selectedGuid : 'x', undefined);

  // Continue is inert. The GUID is the identity, and guessing it for them is how a year of
  // data ends up under the wrong company.
  assert.deepEqual(next(listed, { type: 'continue' }), listed);

  const picked = next(listed, { type: 'select_company', guid: BETA.guid });
  const s = next(picked, { type: 'continue' });
  assert.equal(s.screen, 'connectCloud');
  assert.equal(s.screen === 'connectCloud' ? s.company.guid : '', BETA.guid);
});

test('selecting a company that was not listed is ignored rather than trusted', () => {
  const listed = next(initialState(), { type: 'probe_succeeded', companies: [ACME] });
  assert.deepEqual(next(listed, { type: 'select_company', guid: 'guid-not-real' }), listed);
});

// ---------------------------------------------------------------- screen 2: connect cloud

test('THE ORDER: provisioning is unreachable until the identity keypair exists', () => {
  // IDENTITY_PUBKEY is set as a Vercel env var DURING provision(). If provisioning could start
  // first, the deployed server would hold no public key (or a dead one), and every upload to
  // it would be unreadable forever — discovered weeks later, with no way back.
  const s = drive([{ type: 'probe_succeeded', companies: [ACME] }, { type: 'continue' }]);
  assert.equal(s.screen === 'connectCloud' ? s.phase : '', 'awaitIdentity');

  // A pasted token at this point goes nowhere. The gate is structural, not a comment.
  const pasted = next(s, { type: 'token_pasted', token: 'vercel_pat_xxx' });
  assert.deepEqual(pasted, s);
  assert.notEqual(pasted.screen === 'connectCloud' ? pasted.phase : '', 'provisioning');
});

test('once the identity exists, the token starts provisioning and the pubkey rides along', () => {
  const s = atProvisioning();
  assert.equal(s.screen, 'connectCloud');
  assert.equal(s.screen === 'connectCloud' ? s.phase : '', 'provisioning');
  // Every state on the provisioning path carries it, so provision() cannot be called without it.
  assert.equal(s.screen === 'connectCloud' && s.phase === 'provisioning' ? s.identityPublicKey : '', 'PK_BASE64');
});

test('a blank token is not a submission', () => {
  const s = atAwaitToken();
  assert.deepEqual(next(s, { type: 'token_pasted', token: '   ' }), s);
});

test('provision progress is piped straight through, so the two cannot drift apart', () => {
  const s = next(atProvisioning(), {
    type: 'provision_event',
    event: { kind: 'step', step: 'provision_database', message: 'Creating your database…' },
  });
  assert.equal(s.screen === 'connectCloud' && s.phase === 'provisioning' ? s.step : '', 'provision_database');
  assert.equal(messageOf(s), 'Creating your database…');
});

test('THE ONE MANUAL CLICK is guided, not an error: one action, and it carries the URL', () => {
  const s = next(atProvisioning(), {
    type: 'provision_event',
    event: {
      kind: 'needs_human',
      action: 'install_neon',
      url: 'https://vercel.com/marketplace/neon',
      message: 'Click "Install" on the Neon page, then come back here.',
    },
  });

  assert.equal(s.screen === 'connectCloud' ? s.phase : '', 'needsHuman');
  // Nobody did anything wrong. Vercel has no REST endpoint for accepting Neon's terms.
  assert.equal(isProblem(s), false);

  const action = actionOf(s)!;
  assert.equal(action.kind, 'open_neon');
  assert.equal(action.url, 'https://vercel.com/marketplace/neon');
});

test('a "waiting" tick does not clobber the Neon instruction the owner is reading', () => {
  const needsHuman = next(atProvisioning(), {
    type: 'provision_event',
    event: { kind: 'needs_human', action: 'install_neon', url: 'https://x', message: 'Click Install.' },
  });
  const ticked = next(needsHuman, { type: 'provision_event', event: { kind: 'waiting', message: 'Waiting…' } });
  assert.deepEqual(ticked, needsHuman);
});

test('402 becomes "add a card in Vercel" — the failure that decides a support call\'s length', () => {
  const s = next(atProvisioning(), {
    type: 'provision_failed',
    error: new VercelError('provision_database', 402, 'Vercel needs a payment method on your account before it can create the database.', true),
  });
  assert.equal(isProblem(s), true);
  const a = actionOf(s)!;
  assert.equal(a.kind, 'open_vercel_billing');
  assert.equal(a.url, 'https://vercel.com/account/billing');
});

test('a rejected token asks for a new token, not for a retry that will fail identically', () => {
  const s = next(atProvisioning(), {
    type: 'provision_failed',
    error: new VercelError('verify_token', 401, 'That Vercel token was not accepted. Paste a fresh one from your Vercel account settings.', true),
  });
  assert.equal(actionOf(s)!.kind, 'paste_new_token');
});

test('a name clash offers a new name', () => {
  const s = next(atProvisioning(), {
    type: 'provision_failed',
    error: new VercelError('create_project', 409, 'A project with that name already exists on your Vercel account.', true),
  });
  assert.equal(actionOf(s)!.kind, 'choose_another_name');
});

test('NO STACK TRACE REACHES THE OWNER: an unexpected throw collapses to one sentence', () => {
  // This is the realistic shape of the bug: Vercel changes a response body, `r.store.id` is
  // undefined, and a TypeError with a stack full of file paths escapes. Echoing String(error)
  // is how that ends up in a screenshot attached to a support ticket.
  const boom = new TypeError("Cannot read properties of undefined (reading 'store')");
  boom.stack = "TypeError: Cannot read properties of undefined\n    at VercelClient.provisionNeon (/app/src/onboarding/vercel.ts:212:19)";

  const s = next(atProvisioning(), { type: 'provision_failed', error: boom });
  const m = messageOf(s)!;

  assert.equal(/vercel\.ts|at VercelClient|TypeError|undefined/.test(m), false);
  assert.equal(m.includes('\n'), false);
  assert.equal(actionOf(s)!.kind, 'retry_provision');
});

test('retrying a failed provision REUSES the identity rather than minting a fresh one', () => {
  // Regenerating here would be a quiet catastrophe: the half-built project keeps the old
  // IDENTITY_PUBKEY, and everything the Bridge seals to the new key is unreadable by it.
  const failed = next(atProvisioning(), { type: 'provision_failed', error: new Error('x') });
  const retried = next(failed, { type: 'retry' });

  assert.equal(retried.screen === 'connectCloud' ? retried.phase : '', 'awaitToken');
  assert.equal(
    retried.screen === 'connectCloud' && retried.phase === 'awaitToken' ? retried.identityPublicKey : '',
    'PK_BASE64',
  );
});

test('a stale provisioning event arriving after a failure does not resurrect the screen', () => {
  const failed = next(atProvisioning(), { type: 'provision_failed', error: new Error('x') });
  assert.deepEqual(
    next(failed, { type: 'provision_event', event: { kind: 'step', step: 'deploy', message: 'Deploying…' } }),
    failed,
  );
});

// ---------------------------------------------------------------- screen 3: passphrase

test('a mismatched confirmation is caught with one sentence and one action', () => {
  const s = next(drive([{ type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' }], atProvisioning()), {
    type: 'passphrase_submitted',
    passphrase: PASS,
    confirm: 'something else',
  });
  assert.equal(isProblem(s), true);
  assert.equal(actionOf(s)!.kind, 'choose_another_passphrase');
});

test('length is the rule, not composition theatre', () => {
  // "One uppercase, one digit, one symbol" produces Tally@123 and a sticky note. Length is the
  // only lever that costs an attacker anything.
  assert.equal(checkPassphrase('a'.repeat(MIN_PASSPHRASE_LENGTH), 'a'.repeat(MIN_PASSPHRASE_LENGTH)), undefined);
  assert.match(checkPassphrase('short', 'short')!, /at least/);
  assert.match(checkPassphrase('correct horse', 'correct hors')!, /not the same/);
});

test('a good passphrase leads to wrapping, then the sheet', () => {
  const sheet = sheetFor();
  const s = drive(
    [
      { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    ],
    atProvisioning(),
  );
  assert.equal(s.screen === 'setPassphrase' ? s.phase : '', 'wrapping');
  const withSheet = next(s, { type: 'sheet_ready', sheet });
  assert.equal(withSheet.screen === 'setPassphrase' ? withSheet.phase : '', 'sheet');
});

test('PRINTING PROVES NOTHING and does not advance the wizard', () => {
  // The printer may have been out of toner. Only words read back OFF the paper prove the paper
  // exists and is legible.
  const sheet = sheetFor();
  const atSheet = drive(
    [
      { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'sheet_ready', sheet },
    ],
    atProvisioning(),
  );
  assert.deepEqual(next(atSheet, { type: 'printed' }), atSheet);
});

test('a printer failure keeps the owner on the sheet, and never leaks the printer error', () => {
  // THIS TEST USED TO ASSERT THE BUG. It required `isProblem(s) === true` — i.e. that a print
  // failure moved to the `problem` phase, which carries no `sheet`. That state could never move
  // again ("Print again" no-ops on both success and failure), so setup dead-ended with the
  // passphrase already set and `done` unreachable forever. The test passed the whole time,
  // because it asserted an action EXISTED and never that firing it CHANGED anything.
  //
  // A test that pins the wrong behaviour is worse than no test: it makes the bug load-bearing.
  const s = next(atSheet(), { type: 'print_failed', error: new Error('ENOENT: no printer') });

  assert.equal(phaseOf(s), 'sheet', 'the printer failed; the sheet did not');
  assert.equal(isProblem(s), false, 'a failed print is a note on this screen, not a screen');
  assert.match(String((s as { printProblem?: string }).printProblem), /print it again/i);
  // The owner keeps a way forward that WORKS — see the dead-end test below for the proof it moves.
  assert.notEqual(next(s, { type: 'continue' }), s);

  // The printer's own error text never reaches the owner.
  assert.equal(/ENOENT/.test(String((s as { printProblem?: string }).printProblem)), false);
});

test('the gate challenges words #4 and #17, as printed', () => {
  const s = atVerify();
  assert.deepEqual(s.screen === 'setPassphrase' && s.phase === 'verify' ? s.positions : [], [4, 17]);
});

test('THE GATE IS UNSKIPPABLE: no event in the entire union reaches "done" except a correct answer', () => {
  // This is the test that has to survive every future contributor. If verification lived in a
  // click handler, "skip" would be one `if` away forever. Here, adding a bypass means adding
  // an edge to this machine, in front of a reviewer, and this test goes red.
  const sheet = sheetFor();
  const verify = atVerify(sheet);

  const everyOtherEvent: WizardEvent[] = [
    { type: 'probe_started' },
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'probe_failed', failure: { kind: 'not_running' } },
    { type: 'select_company', guid: ACME.guid },
    { type: 'continue' },
    { type: 'retry' },
    { type: 'identity_ready', identityPublicKey: 'OTHER' },
    { type: 'token_pasted', token: 'tok' },
    { type: 'provision_event', event: { kind: 'step', step: 'done', message: 'Your dashboard is live.' } },
    { type: 'provision_failed', error: new Error('x') },
    { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet: sheetFor(9) },
    { type: 'wrap_failed', error: new Error('x') },
    { type: 'printed' },
    { type: 'print_failed', error: new Error('x') },
    // Wrong answers, in every shape someone might hope short-circuits the check.
    { type: 'verify_submitted', answers: [] },
    { type: 'verify_submitted', answers: ['', ''] },
    { type: 'verify_submitted', answers: ['wrong', 'wrong'] },
    { type: 'verify_submitted', answers: [sheet.words[3]!] },
    { type: 'verify_submitted', answers: [sheet.words[16]!, sheet.words[3]!] },
    { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!, 'extra'] },
  ];

  for (const e of everyOtherEvent) {
    const after = next(verify, e);
    assert.equal(isComplete(after), false, `event ${e.type} escaped the recovery gate`);
    assert.equal(after.screen, 'setPassphrase', `event ${e.type} left the gate`);
  }

  // A fabricated "skip" event is inert too, because it is not in the union at all.
  assert.equal(isComplete(next(verify, { type: 'skip' } as unknown as WizardEvent)), false);

  // And the one true path works.
  const done = next(verify, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  assert.equal(isComplete(done), true);
});

test('wrong answers keep the owner at the gate, counting, but never lock them out', () => {
  // A lockout here would be user-hostile theatre: the person holding the sheet IS the owner,
  // and the sheet is in their hand. This is a typo gate, not an auth boundary.
  const sheet = sheetFor();
  let s = atVerify(sheet);
  for (let i = 1; i <= 20; i++) {
    s = next(s, { type: 'verify_submitted', answers: ['nope', 'nope'] });
    assert.equal(s.screen === 'setPassphrase' ? s.phase : '', 'verify');
    assert.equal(s.screen === 'setPassphrase' && s.phase === 'verify' ? s.attempts : -1, i);
  }
  const done = next(s, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  assert.equal(isComplete(done), true);
});

test('the gate is case- and whitespace-forgiving, because handwriting is', () => {
  const sheet = sheetFor();
  const done = next(atVerify(sheet), {
    type: 'verify_submitted',
    answers: [` ${sheet.words[3]!.toUpperCase()} `, `${sheet.words[16]!} `],
  });
  assert.equal(isComplete(done), true);
});

test('a failed wrap loses nothing and says so, with one action', () => {
  const s = drive(
    [
      { type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' },
      { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
      { type: 'wrap_failed', error: new Error('crypto_pwhash failed: out of memory') },
    ],
    atProvisioning(),
  );
  assert.equal(isProblem(s), true);
  assert.equal(/crypto_pwhash|memory/.test(messageOf(s)!), false);
  assert.equal(actionOf(s)!.kind, 'choose_another_passphrase');
});

// ---------------------------------------------------------------- global properties

/** Every state a determined owner can actually reach, gathered by driving the machine. */
function reachableStates(): WizardState[] {
  const sheet = sheetFor();
  const out: WizardState[] = [];
  const push = (s: WizardState) => out.push(s);

  for (const f of [
    { kind: 'not_running' },
    { kind: 'no_company_open' },
    { kind: 'not_tally', bodyExcerpt: '<html>' },
    { kind: 'tally_error', message: 'Licence not active' },
    { kind: 'timeout', afterMs: 10_000 },
    { kind: 'http_status', status: 502 },
    { kind: 'network', message: 'ECONNREFUSED 127.0.0.1:9000' },
  ] as const) {
    push(next(initialState(), { type: 'probe_failed', failure: f }));
  }

  for (const err of [
    new VercelError('verify_token', 401, 'That Vercel token was not accepted. Paste a fresh one from your Vercel account settings.', true),
    new VercelError('provision_database', 402, 'Vercel needs a payment method on your account before it can create the database.', true),
    new VercelError('create_project', 403, 'That Vercel token does not have permission for this. Create a new token with full account access.', true),
    new VercelError('create_project', 409, 'A project with that name already exists on your Vercel account.', true),
    new VercelError('await_ready', 0, 'The dashboard failed to build on Vercel.'),
    new VercelError('await_neon_install', 0, 'We did not see Neon installed on your Vercel account. Open the Neon page and click Install, then try again.', true),
    new TypeError("Cannot read properties of undefined (reading 'store')"),
    'a bare string thrown from somewhere careless',
    undefined,
  ]) {
    push(next(atProvisioning(), { type: 'provision_failed', error: err }));
  }

  const afterProvision = drive([{ type: 'provision_succeeded', projectId: 'p', deploymentUrl: 'u' }], atProvisioning());
  push(next(afterProvision, { type: 'passphrase_submitted', passphrase: 'a', confirm: 'a' }));
  push(next(afterProvision, { type: 'passphrase_submitted', passphrase: PASS, confirm: 'nope' }));
  push(
    drive(
      [
        { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
        { type: 'wrap_failed', error: new Error('boom') },
      ],
      afterProvision,
    ),
  );
  push(
    drive(
      [
        { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
        { type: 'sheet_ready', sheet },
        { type: 'print_failed', error: new Error('ENOENT') },
      ],
      afterProvision,
    ),
  );
  push(next(atVerify(sheet), { type: 'verify_submitted', answers: ['no', 'no'] }));
  push(
    next(atProvisioning(), {
      type: 'provision_event',
      event: { kind: 'needs_human', action: 'install_neon', url: 'https://vercel.com/marketplace/neon', message: 'Click "Install" on the Neon page, then come back here.' },
    }),
  );

  return out;
}

test('EVERY failure state carries EXACTLY ONE action', () => {
  // One action, not a menu. An owner staring at three buttons at the moment something broke
  // picks none of them and phones you instead.
  const problems = reachableStates().filter(isProblem);
  assert.ok(problems.length >= 12, `expected a real corpus of failures, got ${problems.length}`);

  for (const s of problems) {
    const action = actionOf(s);
    assert.ok(action, `${s.screen}/${phaseOf(s)} offers no way forward`);
    assert.equal(typeof action.label, 'string');
    assert.ok(action.label.length > 0);
    // Singular by type as well as by count: there is no `actions` array anywhere to grow into.
    assert.equal('actions' in s, false, `${s.screen}/${phaseOf(s)} grew an actions list`);
  }
});

test('NO JARGON, NO STACK TRACE, NO RAW ERROR reaches any screen', () => {
  const banned: Array<[RegExp, string]> = [
    [/\bat [A-Za-z$_][\w.$]*\s*\(/, 'a stack frame'],
    [/\.ts:\d+|\.js:\d+/, 'a source location'],
    [/TypeError|ReferenceError|SyntaxError|RangeError/, 'an exception class'],
    [/\bundefined\b|\bnull\b|\bNaN\b/, 'a JS value'],
    [/ECONNREFUSED|ENOENT|EADDRINUSE|ETIMEDOUT/, 'an errno'],
    [/[{}[\]<>]/, 'markup or a serialized object'],
    [/\n/, 'a multi-line dump'],
    [/\bHTTP \d|\bstatus \d/i, 'a status code'],
    [/\bexception\b|\bstack\b|\btrace\b/i, 'implementation vocabulary'],
  ];

  for (const s of reachableStates()) {
    const m = messageOf(s);
    if (m === undefined) continue;
    for (const [re, what] of banned) {
      assert.equal(re.test(m), false, `${s.screen}/${phaseOf(s)} shows ${what}: ${JSON.stringify(m)}`);
    }
    // A sentence, not a fragment: capitalised and terminated.
    assert.match(m, /^[A-Z"“]/, `not a sentence: ${JSON.stringify(m)}`);
    assert.match(m, /[.!?…]$/, `not terminated: ${JSON.stringify(m)}`);
  }
});

test('every action label is something an owner could act on, not a verb from our codebase', () => {
  for (const s of reachableStates()) {
    const a = actionOf(s);
    if (!a) continue;
    assert.equal(/provision|icfg|env var|payload|API|token expired/i.test(a.label), false, `jargon in "${a.label}"`);
    if (a.url !== undefined) assert.match(a.url, /^https:\/\//);
  }
});

test('done is terminal: nothing un-does a finished setup', () => {
  const sheet = sheetFor();
  const done = next(atVerify(sheet), { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  for (const e of [{ type: 'retry' }, { type: 'probe_started' }, { type: 'continue' }] as WizardEvent[]) {
    assert.deepEqual(next(done, e), done);
  }
  assert.equal(actionOf(done), undefined);
  assert.equal(messageOf(done), undefined);
});

test('next() is pure: it never mutates the state it was given', () => {
  const before = atProvisioning();
  const snapshot = structuredClone(before);
  next(before, { type: 'provision_event', event: { kind: 'step', step: 'deploy', message: 'Deploying…' } });
  next(before, { type: 'provision_failed', error: new Error('x') });
  assert.deepEqual(before, snapshot);
});

test('THE HAPPY PATH, end to end, in the order the crypto requires', () => {
  const sheet = sheetFor();
  const s = drive([
    { type: 'probe_succeeded', companies: [ACME] },
    { type: 'continue' },
    // Identity BEFORE the token — IDENTITY_PUBKEY has to exist to be set during provisioning.
    { type: 'identity_ready', identityPublicKey: 'PK_BASE64' },
    { type: 'token_pasted', token: 'vercel_pat_xxx' },
    { type: 'provision_event', event: { kind: 'step', step: 'create_project', message: 'Creating your project…' } },
    { type: 'provision_event', event: { kind: 'needs_human', action: 'install_neon', url: 'https://vercel.com/marketplace/neon', message: 'Click "Install" on the Neon page, then come back here.' } },
    { type: 'provision_event', event: { kind: 'step', step: 'deploy', message: 'Deploying…' } },
    { type: 'provision_succeeded', projectId: 'prj_1', deploymentUrl: 'https://acme.vercel.app' },
    // Only now is the key wrapped — under the passphrase AND the recovery key.
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'sheet_ready', sheet },
    { type: 'printed' },
    { type: 'continue' },
    { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] },
  ]);

  assert.equal(isComplete(s), true);
  assert.equal(s.screen === 'done' ? s.deploymentUrl : '', 'https://acme.vercel.app');
  assert.equal(s.screen === 'done' ? s.company.guid : '', ACME.guid);
});

// ---------------------------------------------------------------- ADVERSARIAL: the gate

test('THE GATE: a malformed answer array cannot reach done', () => {
  // The machine claims `done` is unreachable except through a correct answer. The check itself
  // compared `answers[i]?.trim().toLowerCase()` against `sheet.words[pos - 1]` — both undefined
  // when the sheet is short and the answer is missing, which is a match. `verify_submitted`
  // arrives over IPC from the renderer, so its payload is not something this machine may assume
  // is well-formed.
  const short = { words: ['a', 'b', 'c', 'four'], keyBase64: 'k', businessName: 'B', createdOn: 'd' } as RecoverySheet;
  const ctx = {
    company: { guid: 'g', name: 'N' },
    identityPublicKey: 'pk',
    projectId: 'p',
    deploymentUrl: 'u',
  };
  let s: WizardState = { screen: 'setPassphrase', phase: 'sheet', ctx, sheet: short };
  s = next(s, { type: 'continue' });
  assert.equal(phaseOf(s), 'verify');

  for (const answers of [
    ['four', undefined],
    ['four', null],
    [undefined, undefined],
    [null, null],
  ] as unknown as string[][]) {
    const out = next(s, { type: 'verify_submitted', answers });
    assert.notEqual(out.screen, 'done', `answers ${JSON.stringify(answers)} must not open the gate`);
  }
});

test('THE GATE: no secret survives into the terminal state', () => {
  // `done` is the state that outlives the wizard — it is what a driver is most likely to log or
  // persist. The recovery key and the words must not be in it.
  const sheet = makeRecoverySheet(new Uint8Array(32).fill(9), 'Acme', '2026-07-16');
  const ctx = {
    company: { guid: 'g', name: 'N' },
    identityPublicKey: 'pk',
    projectId: 'p',
    deploymentUrl: 'u',
  };
  let s: WizardState = { screen: 'setPassphrase', phase: 'sheet', ctx, sheet };
  s = next(s, { type: 'continue' });
  s = next(s, { type: 'verify_submitted', answers: [sheet.words[3]!, sheet.words[16]!] });
  assert.equal(s.screen, 'done');

  const dump = JSON.stringify(s);
  assert.ok(!dump.includes(sheet.keyBase64), 'the recovery key must not survive into done');
  for (const w of sheet.words) assert.ok(!dump.includes(`"${w}"`), 'no recovery word may survive into done');
});

test('a passphrase never enters wizard state', () => {
  const ctx = {
    company: { guid: 'g', name: 'N' },
    identityPublicKey: 'pk',
    projectId: 'p',
    deploymentUrl: 'u',
  };
  const entry: WizardState = { screen: 'setPassphrase', phase: 'entry', ctx };
  const PASS = 'correct horse battery staple';
  for (const ev of [
    { type: 'passphrase_submitted', passphrase: PASS, confirm: PASS },
    { type: 'passphrase_submitted', passphrase: PASS, confirm: 'mismatch' },
    { type: 'passphrase_submitted', passphrase: 'hunter2', confirm: 'hunter2' },
  ] as WizardEvent[]) {
    const out = next(entry, ev);
    assert.ok(!JSON.stringify(out).includes(PASS), 'the passphrase must never land in state');
    assert.ok(!JSON.stringify(out).includes('hunter2'), 'nor a rejected one');
  }
});

test('a Vercel token never enters wizard state', () => {
  const s: WizardState = {
    screen: 'connectCloud', phase: 'awaitToken', company: { guid: 'g', name: 'N' }, identityPublicKey: 'pk',
  };
  const out = next(s, { type: 'token_pasted', token: 'tok_SECRET_PAT' });
  assert.ok(!JSON.stringify(out).includes('tok_SECRET_PAT'));
});

test('a print failure keeps the sheet, and every escape from it actually MOVES', () => {
  // THE BUG THIS PINS: `print_failed` used to move to `phase: 'problem'`, which carries no
  // `sheet`. The sheet was gone and nothing could restore it. The only action was "Print again":
  // on success it sends `printed` (a deliberate no-op) and on failure `print_failed` (ignored off
  // the sheet phase) — so the state could never move again. Passphrase set, identity wrapped,
  // `done` unreachable FOREVER.
  //
  // It was reachable by the DEFAULT path: the wizard auto-fires the print dialog, and pressing
  // Esc on a dialog you did not ask for is the normal human response.
  const sheet = sheetFor();
  const at = atSheet(sheet);
  assert.equal(phaseOf(at), 'sheet');

  const failed = next(at, { type: 'print_failed', error: new Error('user cancelled') });
  assert.equal(phaseOf(failed), 'sheet', 'a printer failure must not cost the owner the sheet');
  assert.deepEqual(
    (failed as { sheet?: RecoverySheet }).sheet,
    sheet,
    'the words and QR are still correct — the printer failed, the sheet did not',
  );
  assert.match(String((failed as { printProblem?: string }).printProblem), /print/i);

  // THE ESCAPE MOVES. This is what the old "never a dead end" test failed to check: it asserted
  // an action EXISTED, never that firing it CHANGED anything.
  const onward = next(failed, { type: 'continue' });
  assert.notDeepEqual(onward, failed, 'Continue must move — an action that no-ops IS the dead end');
  assert.equal(phaseOf(onward), 'verify', 'and it must reach the gate, not wander');

  // Retrying the print succeeds and the stale failure note is cleared.
  const printedOk = next(failed, { type: 'printed' });
  assert.equal((printedOk as { printProblem?: string }).printProblem, undefined,
    'a "we could not print" note under a sheet that just printed is its own small lie');
  assert.equal(phaseOf(printedOk), 'sheet', 'printing still proves nothing; only the words do');
});

test('a print failure cannot be used to walk past the verification gate', () => {
  // The gate is the product's one unskippable step. Confirm the new escape hatch is not a hole:
  // reaching `verify` from a print failure must still demand the correct words.
  const sheet = sheetFor();
  const failed = next(atSheet(sheet), { type: 'print_failed', error: 'cancelled' });
  const gate = next(failed, { type: 'continue' });
  assert.equal(phaseOf(gate), 'verify');

  const wrong = next(gate, { type: 'verify_submitted', answers: ['wrong', 'wrong'] });
  assert.notEqual(wrong.screen, 'done', 'a print failure must not become a skip button');
  assert.equal(phaseOf(wrong), 'verify');
});
