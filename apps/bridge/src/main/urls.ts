import { fileURLToPath } from 'node:url';
import { isAbsolute, relative, resolve } from 'node:path';

/**
 * URL policy: the two predicates that decide what this app will navigate to and what it will
 * hand to the OS.
 *
 * This module deliberately imports NO Electron. It used to live inside window.ts, which meant it
 * could not be imported by a test (`electron` cannot be required outside an Electron process) —
 * so the test re-implemented it by hand, and a re-implementation is a copy that agrees with the
 * original only until someone edits one of them. `shell.openExternal` is a code-execution
 * primitive; its allowlist is not something to test by lookalike.
 *
 * There is exactly ONE copy of each rule, and the tests import THIS.
 */

/** Content-Security-Policy. No `unsafe-inline`, no remote origins. */
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  // The renderer talks to the main process over IPC, never over the network. The dashboard
  // fetches happen in the MAIN process, so the renderer needs no connect-src at all.
  "connect-src 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join('; ');

/**
 * May this window navigate to `url`?
 *
 * `protocol === 'file:'` is NOT sufficient, and the gap is a real escalation path. Every file:
 * URL passes such a check, including:
 *
 *   - `file:///C:/Users/owner/Downloads/invoice.html` — anything the owner was talked into
 *     downloading. It loads in THIS window, which means it inherits the preload bridge.
 *   - `file://attacker.example/share/x.html` — a UNC path. On Windows that is a live SMB fetch
 *     of REMOTE content wearing a local scheme, and it also leaks an NTLM handshake to the host.
 *
 * The app ships its renderer inside one directory and never navigates outside it, so the
 * predicate is containment, not scheme-checking.
 */
export function isLocalAsset(url: string, rootDir: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'file:') return false;

  // A non-empty host is a UNC path: remote content, local scheme. `fileURLToPath` would also
  // throw for most of these off-Windows, but relying on a throw for a security decision means
  // the rule changes with the platform.
  if (u.hostname !== '' && u.hostname !== 'localhost') return false;

  // A file: URL cannot carry these, but a parser that produced them means we do not understand
  // the input well enough to hand it to Chromium.
  if (u.username !== '' || u.password !== '' || u.port !== '') return false;

  let path: string;
  try {
    // Decodes percent-escapes, so `%2e%2e%2f` becomes `../` HERE rather than inside Chromium.
    path = fileURLToPath(u);
  } catch {
    return false;
  }

  // `relative` resolves `..` segments; anything still climbing out of the root escapes it.
  // (On Windows this comparison is case-insensitive, which is what that filesystem means.)
  const rel = relative(resolve(rootDir), resolve(path));
  if (rel === '') return false;
  return !rel.startsWith('..') && !isAbsolute(rel);
}

const ALLOWED_HOSTS = ['vercel.com', 'neon.tech'] as const;
const ALLOWED_SUFFIXES = ['.vercel.com', '.neon.tech', '.vercel.app'] as const;

/**
 * Only ever hand https: URLs on the allowlist to the OS browser.
 *
 * `shell.openExternal` will happily execute `file:///...` and, on Windows, every registered
 * protocol handler — so passing an unvalidated URL here is a code-execution primitive, not a
 * convenience. The allowlist is the point.
 *
 * Returns the NORMALIZED href to pass on, rather than a boolean, so that the string which was
 * validated is the string which gets executed. Handing the caller's original text to the OS
 * after validating a parse of it is how parser-differential bugs turn into RCE.
 */
export function safeExternalUrl(url: string): string | undefined {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return undefined;
  }
  if (u.protocol !== 'https:') return undefined;

  // `https://vercel.com@evil.com` already fails the host check below — `hostname` is `evil.com`,
  // which is the whole reason we parse instead of string-match. This rejects the INVERSE:
  // `https://owner:hunter2@vercel.com`, a real host carrying credentials we would otherwise
  // hand to a browser (and its history, and its crash reports).
  if (u.username !== '' || u.password !== '') return undefined;

  // `hostname` is already IDNA/punycode-normalized by the WHATWG parser, so an IDN homograph
  // (`vercеl.com` with a Cyrillic е) arrives here as `xn--vercl-8ve.com` and simply misses the
  // allowlist. Lowercasing is for ASCII case only.
  const host = u.hostname.toLowerCase();
  const allowed =
    (ALLOWED_HOSTS as readonly string[]).includes(host) ||
    ALLOWED_SUFFIXES.some((s) => host.endsWith(s));
  if (!allowed) return undefined;

  return u.toString();
}

/** Boolean form, for call sites that only branch. */
export function isSafeExternal(url: string): boolean {
  return safeExternalUrl(url) !== undefined;
}
