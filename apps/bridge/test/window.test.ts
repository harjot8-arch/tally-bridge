import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join, sep } from 'node:path';
import { isLocalAsset, isSafeExternal, safeExternalUrl } from '../src/main/urls.ts';

/**
 * The URL policy — the allowlist that stands between a compromised renderer and
 * `shell.openExternal`, which is a code-execution primitive on Windows.
 *
 * These import the REAL predicates. They used to re-implement them inline, because window.ts
 * imports `electron` and could not be loaded outside an Electron process — but a
 * re-implementation is a copy that agrees with the original only until someone edits one of
 * them, and "the test passes; the shipped allowlist is different" is precisely how this class of
 * bug survives review. The predicates now live in `src/main/urls.ts`, which imports no Electron.
 */

const ROOT = join(sep, 'app', 'dist');
const local = (url: string) => isLocalAsset(url, ROOT);

test('the onboarding hosts we actually need are allowed', () => {
  assert.ok(isSafeExternal('https://vercel.com/account/tokens'));
  assert.ok(isSafeExternal('https://vercel.com/marketplace/neon'));
  assert.ok(isSafeExternal('https://acme-dash.vercel.app'));
  assert.ok(isSafeExternal('https://console.neon.tech'));
});

test('THE RCE VECTOR: non-https protocols are refused', () => {
  // shell.openExternal executes whatever protocol handler the URL names. On Windows that
  // includes file:, ms-msdt:, and every registered custom scheme — so an unvalidated URL from
  // a compromised renderer is arbitrary code execution, not a link.
  assert.equal(isSafeExternal('file:///C:/Windows/System32/cmd.exe'), false);
  assert.equal(isSafeExternal('javascript:alert(1)'), false);
  assert.equal(isSafeExternal('ms-msdt:/id PCWDiagnostic'), false);
  assert.equal(isSafeExternal('vbscript:msgbox(1)'), false);
  assert.equal(isSafeExternal('data:text/html,<script>alert(1)</script>'), false);
  assert.equal(isSafeExternal('smb://attacker/share'), false);
});

test('http is refused even for an allowed host', () => {
  // Downgrade is a real attack on a hostile network, and there is no reason to ever need it.
  assert.equal(isSafeExternal('http://vercel.com'), false);
});

test('SUFFIX CONFUSION: lookalike hosts do not slip through', () => {
  // The classic endsWith() bug. `notvercel.com` ends with... nothing we allow, because the
  // checks anchor on a leading dot or an exact match.
  assert.equal(isSafeExternal('https://evilvercel.com'), false);
  assert.equal(isSafeExternal('https://vercel.com.evil.tld'), false);
  assert.equal(isSafeExternal('https://notneon.tech'), false);
  assert.equal(isSafeExternal('https://fakevercel.app'), false);
});

test('userinfo cannot be used to spoof the host', () => {
  // https://vercel.com@evil.com/ — the browser goes to evil.com. URL parsing gets this right;
  // naive string matching would not.
  assert.equal(isSafeExternal('https://vercel.com@evil.com/'), false);
  assert.equal(isSafeExternal('https://vercel.com:pass@evil.com/'), false);
  // The percent-encoded variant: `%2f` inside userinfo does NOT terminate it, so the host is
  // still evil.com. A hand-rolled "split on the first slash" check would read this as vercel.com.
  assert.equal(isSafeExternal('https://vercel.com%2f@evil.com/'), false);
  assert.equal(isSafeExternal('https://vercel.com%40evil.com/'), false);
  // Backslashes are normalized to forward slashes by the WHATWG parser, so this is
  // `https://evil.com/vercel.com` — path, not host.
  assert.equal(isSafeExternal('https:\\\\evil.com\\vercel.com'), false);
});

test('CREDENTIALS are refused even on an allowed host', () => {
  // The inverse of the spoof above: a REAL allowed host carrying userinfo. We would be handing
  // a credential to the OS browser, which puts it in history, in sync, and in crash reports.
  // There is no legitimate reason for one of our own links to carry a password.
  assert.equal(isSafeExternal('https://owner:hunter2@vercel.com/account'), false);
  assert.equal(isSafeExternal('https://token@api.vercel.com/v13/deployments'), false);
});

test('IDN HOMOGRAPHS cannot impersonate an allowed host', () => {
  // `vercеl.com` with a Cyrillic U+0435 renders identically to `vercel.com` in most fonts. The
  // WHATWG parser applies IDNA/punycode to `hostname`, so it arrives as xn--... and misses the
  // allowlist. This asserts we RELY on that rather than on a raw string compare.
  assert.equal(isSafeExternal('https://vercеl.com'), false);
  assert.equal(isSafeExternal('https://neon.tеch'), false);
  // U+3002 IDEOGRAPHIC FULL STOP is mapped to "." by IDNA, so this is vercel.com.evil.tld.
  assert.equal(isSafeExternal('https://vercel.com。evil.tld'), false);
  // Fullwidth solidus / other separators must not manufacture an allowed suffix either.
  assert.equal(isSafeExternal('https://evil.com／.vercel.com'), false);
});

test('a trailing-dot FQDN does not bypass the allowlist', () => {
  // `vercel.com.` is the same host to DNS but a different string to endsWith(). It must fail
  // CLOSED (we lose nothing by refusing) rather than open.
  assert.equal(isSafeExternal('https://vercel.com./account'), false);
  assert.equal(isSafeExternal('https://evil.com/.vercel.com'), false);
});

test('subdomains of allowed hosts are fine', () => {
  assert.ok(isSafeExternal('https://api.vercel.com/v13/deployments'));
  assert.ok(isSafeExternal('https://anything.neon.tech'));
});

test('host matching is case-insensitive', () => {
  assert.ok(isSafeExternal('https://VERCEL.COM/account/tokens'));
});

test('garbage does not throw', () => {
  assert.equal(isSafeExternal('not a url'), false);
  assert.equal(isSafeExternal(''), false);
  assert.equal(isSafeExternal('https://'), false);
});

test('THE VALIDATED STRING IS THE EXECUTED STRING', () => {
  // safeExternalUrl returns the normalized href rather than a boolean, so a caller cannot
  // validate a parse of the URL and then hand the ORIGINAL text to the OS. That gap is where
  // parser differentials (Node parsed it one way, Chromium/the shell another) become RCE.
  assert.equal(safeExternalUrl('https://vercel.com'), 'https://vercel.com/');
  assert.equal(safeExternalUrl('https://VERCEL.COM/Account'), 'https://vercel.com/Account');
  assert.equal(safeExternalUrl('https://evil.com'), undefined);
});

// ---------------------------------------------------------------- navigation

test('navigation is restricted to the app bundle', () => {
  // If a renderer is compromised, the attacker navigates it to a page they control — which
  // then inherits the preload bridge. This app is a local UI; it never navigates out.
  assert.ok(local(pathToFileURL(join(ROOT, 'renderer', 'index.html')).href));
  assert.equal(local('https://evil.com'), false);
  assert.equal(local('http://localhost:3000'), false);
  assert.equal(local('data:text/html,x'), false);
  assert.equal(local('not a url'), false);
});

test('THE FILE: HOLE — an arbitrary local file is not an app asset', () => {
  // `protocol === 'file:'` was the whole check, and every one of these passes it. Each loads in
  // the EXISTING window, which means it keeps the preload bridge — so a single downloaded HTML
  // file the owner was talked into opening becomes a call into the main process.
  assert.equal(local(pathToFileURL(join(sep, 'Users', 'owner', 'Downloads', 'invoice.html')).href), false);
  assert.equal(local(pathToFileURL(join(sep, 'etc', 'passwd')).href), false);
  assert.equal(local('file:///C:/Windows/System32/drivers/etc/hosts'), false);
});

test('THE UNC HOLE — remote content wearing a local scheme', () => {
  // file://attacker/share/x.html is a live SMB fetch on Windows: attacker-controlled bytes in a
  // window with the bridge attached, plus a leaked NTLM handshake for the trouble.
  assert.equal(local('file://attacker.example/share/payload.html'), false);
  assert.equal(local('file://10.0.0.5/c$/payload.html'), false);
});

test('TRAVERSAL out of the app root is refused after decoding', () => {
  // The escape must be resolved before the decision, not after: `%2e%2e%2f` is `../` to
  // Chromium, and a check that runs on the raw string never sees it.
  assert.equal(local(`file://${ROOT}/renderer/../../../etc/passwd`), false);
  assert.equal(local(`file://${ROOT}/renderer/%2e%2e/%2e%2e/%2e%2e/etc/passwd`), false);
  assert.equal(local(`file://${ROOT}/../secrets.html`), false);
  // A sibling directory that merely shares a prefix — /app/dist-evil vs /app/dist. A
  // startsWith() containment check gets this wrong; path.relative does not.
  assert.equal(local(pathToFileURL(join(sep, 'app', 'dist-evil', 'x.html')).href), false);
});

test('the app root itself is not a navigable asset', () => {
  assert.equal(local(pathToFileURL(ROOT).href), false);
});
