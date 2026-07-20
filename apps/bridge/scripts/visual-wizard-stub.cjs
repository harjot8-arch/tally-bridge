// Fake `window.bridge` for the WIZARD screens. See visual-harness.mjs.
//
// ---------------------------------------------------------------------------------------------
// THE STATES ARE PRODUCED BY THE REAL STATE MACHINE.
//
// Same principle as visual-stub.cjs: nothing here invents a shape. `initialState()` and `next()`
// are the actual machine from src/onboarding/wizard.ts (via dist), driven with the actual
// events, so every screenshot is of a state the product can really be in. A hand-written state
// object would be a picture of my idea of the wizard rather than of the wizard — and this file's
// sibling proved how fast that goes wrong (it invented `CashBankCard.rows`, and the page died).
//
// These are the highest-stakes screens in the product and nobody had ever looked at them. The
// passphrase screen is where an owner chooses the thing that protects every number they have;
// the recovery sheet is the only backup if they forget it, and the plan is explicit that an
// unverified recovery key is worse than none because it manufactures false confidence.
const { join } = require('node:path');

const M = join(__dirname, '../dist/onboarding/wizard.js');
const { initialState, next } = require(M);

/** Walk the real machine to a named screen with the real events. */
function driveTo(target) {
  let s = initialState();
  if (target === 'findTally') return s;

  s = next(s, {
    type: 'probe_succeeded',
    companies: [
      { guid: 'guid-a', name: 'Acme Traders' },
      // A hostile name on the one screen that lists them back to the owner.
      { guid: 'guid-b', name: 'A & B Traders <Mumbai>' },
    ],
  });
  if (target === 'pickCompany') return s;

  s = next(s, { type: 'select_company', guid: 'guid-a' });
  s = next(s, { type: 'continue' });

  // `identity_ready` MUST precede provisioning — the machine says so at the event's definition,
  // and it is not ceremony: the identity public key is set as an env var BEFORE the first
  // deploy, so a deployment that raced ahead of the keypair would serve a dashboard bound to no
  // identity. Omitting it here parked the machine on "Getting ready / Preparing the lock" and
  // three different screenshots came out as the same screen — which is how I found this.
  s = next(s, { type: 'identity_ready', identityPublicKey: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=' });
  if (target === 'connectCloud') return s;

  s = next(s, { type: 'token_pasted', token: 'vercel_tok_example' });
  if (target === 'provisioning') return s;

  // Flat fields, not a `cloud` object: `{ projectId, deploymentUrl }` is the real shape. The
  // tenantId and bootstrapSecret never cross this event — they stay in the driver.
  s = next(s, {
    type: 'provision_succeeded',
    projectId: 'prj_1',
    deploymentUrl: 'https://acme-traders-dash.vercel.app',
  });
  if (target === 'setPassphrase') return s;

  s = next(s, {
    type: 'passphrase_submitted',
    passphrase: 'a sensible passphrase',
    confirm: 'a sensible passphrase',
  });
  if (target === 'wrapping') return s;

  s = next(s, { type: 'sheet_ready', sheet: SHEET });
  if (target === 'sheet') return s;

  s = next(s, { type: 'continue' });
  return s; // verify
}

/**
 * A recovery sheet with 24 DISTINCT words.
 *
 * Distinctness is not decoration. `new Uint8Array(32).fill(7)` was used as a fixture in the test
 * suite and BIP39 packs 11 bits per word, so the entropy repeated on an 8-word cycle: word #17
 * WAS word #1, and every "reject the wrong word" assertion was vacuously accepting the right
 * one. A screenshot of a sheet with repeated words would hide the same thing from the eye.
 */
const WORDS = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
  'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
  'across', 'act', 'action', 'actor', 'actress', 'actual',
];

const SHEET = {
  words: WORDS,
  // Blanked exactly as `redactForRenderer` blanks it before it crosses IPC — the raw recovery
  // key never reaches the renderer, and a harness that handed one over would be drawing a screen
  // the product cannot produce.
  keyBase64: '',
  businessName: 'Acme Traders',
  createdOn: '2026-07-16',
};

function stubFor(target) {
  const state = driveTo(target);
  return `
window.bridge = {
  isProvisioned: async () => false,
  getStatus: async () => ({ state: 'never', message: 'Not synced yet' }),
  onStatusChanged: () => {},
  syncNow: async () => {},
  getCards: async () => ({ state: 'empty' }),
  getWizardState: async () => (${JSON.stringify(state)}),
  sendWizardEvent: async () => (${JSON.stringify(state)}),
  onWizardStateChanged: () => (() => {}),
  openExternal: async () => {},
  // A 1x1 PNG: the sheet screen refuses anything that is not a raster data URL of the exact
  // shape it validates (this codebase has already had an HTML injection through a QR data URL),
  // so a placeholder string would render the refusal rather than the screen.
  recoveryQr: async () => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  printRecoverySheet: async () => {},
};
`;
}

module.exports = { stubFor, driveTo };
