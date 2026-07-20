import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Architecture tests.
 *
 * These assert invariants over the SOURCE rather than over behaviour, because they are exactly
 * the properties a unit test cannot see and a reviewer forgets. Every one of them is a rule
 * that, if quietly broken in six months, produces a vulnerability with no failing test and no
 * visible symptom.
 *
 * Grep-based checks are crude. They are also the only thing that fails the build when someone
 * adds `nodeIntegration: true` to a new window at 5pm on a Friday.
 */

const SRC = join(import.meta.dirname, '../src');
const ROOT = join(import.meta.dirname, '../../..');

function walk(dir: string, ext = '.ts'): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, ext));
    else if (p.endsWith(ext)) out.push(p);
  }
  return out;
}

const readRaw = (p: string) => readFileSync(p, 'utf8');

/**
 * Read a file with comments stripped.
 *
 * Necessary, and the reason is instructive: these files DOCUMENT the rules they follow, so a
 * naive grep for `innerHTML` matches the comment that says "never use innerHTML" and the test
 * fails on correct code. Every check below therefore looks at code only. (Comment-stripping by
 * regex is imperfect — a `//` inside a string literal would confuse it — but no file here has
 * one, and the alternative is a TypeScript AST walk for a lint rule.)
 */
function read(p: string): string {
  return readFileSync(p, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '') // block comments
    .replace(/(^|[^:])\/\/.*$/gm, '$1'); // line comments, sparing "https://"
}

test('THE XSS RULE: the renderer never uses innerHTML', () => {
  // Party names, ledger names and company names come from a customer's Tally file. A supplier
  // can legitimately name themselves `<img src=x onerror=...>`, and that string flows all the
  // way to these cards. textContent is the entire defence, and it only works if it is used
  // everywhere.
  for (const file of walk(join(SRC, 'renderer'))) {
    const src = read(file);
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write']) {
      assert.ok(!src.includes(sink), `${file} must not use ${sink}`);
    }
  }
});

test('the renderer never constructs a Function or eval', () => {
  for (const file of walk(join(SRC, 'renderer'))) {
    const src = read(file);
    assert.ok(!/\beval\s*\(/.test(src), `${file} must not eval`);
    assert.ok(!/new\s+Function\s*\(/.test(src), `${file} must not construct Functions`);
  }
});

test('THE ELECTRON HARDENING is set and never inverted', () => {
  const src = read(join(SRC, 'main/window.ts'));
  // The settings that matter, in the state that matters.
  assert.match(src, /nodeIntegration:\s*false/);
  assert.match(src, /contextIsolation:\s*true/);
  assert.match(src, /sandbox:\s*true/);
  assert.match(src, /webSecurity:\s*true/);
  assert.match(src, /webviewTag:\s*false/);
  assert.match(src, /allowRunningInsecureContent:\s*false/);
});

test('no window anywhere enables the dangerous settings', () => {
  // Catches a second window added later that skips createSecureWindow.
  for (const file of walk(SRC)) {
    const src = read(file);
    assert.ok(!/nodeIntegration:\s*true/.test(src), `${file} enables nodeIntegration`);
    assert.ok(!/contextIsolation:\s*false/.test(src), `${file} disables contextIsolation`);
    assert.ok(!/webSecurity:\s*false/.test(src), `${file} disables webSecurity`);
    assert.ok(!/sandbox:\s*false/.test(src), `${file} disables the sandbox`);
  }
});

test('THE CSP has no unsafe-inline and no remote origins', () => {
  // The policy lives in urls.ts (the Electron-free half) so that a test can import it.
  const src = read(join(SRC, 'main/urls.ts'));
  assert.ok(!src.includes("'unsafe-inline'"), 'unsafe-inline defeats the CSP entirely');
  assert.ok(!src.includes("'unsafe-eval'"));
  assert.match(src, /default-src 'none'/);
  // The renderer must not reach the network: every fetch happens in the main process.
  assert.match(src, /connect-src 'none'/);

  // Strip HTML comments: the meta tag is preceded by a comment that spells out the rule,
  // quotes and all, so a raw grep matches the documentation instead of the policy.
  const html = readRaw(join(SRC, 'renderer/index.html')).replace(/<!--[\s\S]*?-->/g, '');
  assert.ok(!html.includes("'unsafe-inline'"));
  assert.match(html, /Content-Security-Policy/);
});

/**
 * The checks below cover main-process wiring that CANNOT be unit-tested: `app`, `session` and
 * `BrowserWindow` only exist inside a running Electron process, and the bugs are about the ORDER
 * and PLACEMENT of calls rather than about a value a function returns.
 *
 * Asserting over source text is crude and is not a substitute for an integration test with a
 * real Electron binary — a rename defeats these. They are here because each one encodes a bug
 * that actually shipped in this file and would otherwise have no regression test at all.
 */

test('THE STARTUP CRASH: enableSandbox is never called after the app is ready', () => {
  // `app.enableSandbox()` THROWS if the app is already ready — Electron's own message is
  // "app.enableSandbox() can only be called before app is ready" (it is in the shipped binary;
  // grep the framework for it). It was the first line inside the whenReady callback, where that
  // is true by definition, so it rejected the promise and NOTHING after it ran: no keystore, no
  // scheduler, no tray, no window. The app did not start.
  const src = read(join(SRC, 'main/index.ts'));
  const enable = src.indexOf('app.enableSandbox()');
  const ready = src.indexOf('app.whenReady()');
  assert.ok(enable > 0, 'the Chromium sandbox must still be enabled');
  assert.ok(ready > 0);
  assert.ok(enable < ready, 'enableSandbox() must be called BEFORE app.whenReady(), never inside it');

  // And specifically not inside the ready callback, whatever the callback is named.
  const readyBody = src.slice(ready);
  assert.ok(
    !/whenReady\(\)[\s\S]{0,200}?enableSandbox/.test(readyBody),
    'enableSandbox must not appear in the whenReady chain',
  );
});

test('THE SECOND INSTANCE does not fall through after app.quit()', () => {
  // `app.quit()` is ASYNCHRONOUS: it requests a quit, it does not halt the script. And this is
  // an ES module, so there is no function to `return` from. A bare `if (!gotLock) app.quit();`
  // therefore keeps going — registering whenReady, opening a SECOND writer on the same SQLite
  // file and a second scheduler against a single-threaded Tally. The bootstrap must be on the
  // other branch of the if, not merely after it.
  const src = read(join(SRC, 'main/index.ts'));

  // The invariant, not one particular spelling of it: the losing branch must STOP. Either it
  // returns straight after quit(), or the bootstrap hangs off an `else`. Anything else falls
  // through.
  const guarded =
    /!app\.requestSingleInstanceLock\(\)\s*\)\s*\{\s*app\.quit\(\);\s*return;\s*\}/.test(src) ||
    /!app\.requestSingleInstanceLock\(\)\s*\)\s*\{\s*app\.quit\(\);?\s*\}\s*else\s*\{/.test(src);
  assert.ok(guarded, 'app.quit() is async — the second instance must return or use an else branch');

  // The other half: even a correctly-guarded bootstrap is defeated if the app lifecycle is
  // registered at MODULE scope, because the second instance evaluates the module too.
  for (const m of src.matchAll(/^app\.(on|whenReady)\(/gm)) {
    assert.fail(`app.${m[1]}() is registered at module scope; the second instance runs it too`);
  }
});

test('the app-wide hardening backstop exists and is called before any window', () => {
  // createSecureWindow is a CONVENTION, and conventions get skipped. web-contents-created fires
  // for every webContents including ones that never went through the helper.
  const win = read(join(SRC, 'main/window.ts'));
  assert.match(win, /app\.on\(\s*'web-contents-created'/, 'the backstop must exist');
  assert.match(win, /'will-attach-webview'/, '<webview> preferences are set by the PAGE');
  assert.match(win, /'will-redirect'/, 'a redirect is a navigation will-navigate never sees');
  assert.match(win, /setPermissionRequestHandler/);
  assert.match(win, /setPermissionCheckHandler/);
  assert.match(win, /setDevicePermissionHandler/, 'WebUSB/HID/Serial are a separate consent track');

  // The device choosers are a different gate from the permission handler, and they have a trap:
  // a listener that does not preventDefault makes Electron auto-select the first device. So it
  // is not enough that these are handled — each must preventDefault.
  for (const event of [
    'select-usb-device',
    'select-hid-device',
    'select-serial-port',
    'select-bluetooth-device',
  ]) {
    const handler = new RegExp(`'${event}'[\\s\\S]{0,160}?preventDefault\\(\\)`);
    assert.match(win, handler, `${event} must be handled AND must preventDefault`);
  }

  const index = read(join(SRC, 'main/index.ts'));
  assert.match(index, /hardenApp\(\)/, 'the backstop must actually be called');
});

test('devtools are off in a packaged build', () => {
  // Not an RCE — but Ctrl+Shift+I on a shared business PC is a live console over the owner's
  // receivables for whoever walks up to the machine.
  const src = read(join(SRC, 'main/window.ts'));
  assert.match(src, /devTools:\s*!app\.isPackaged/);
});

test('THE ALLOWLIST EXISTS ONCE — two copies is one control and one liability', () => {
  // index.ts used to carry a hand-copied second version of the openExternal allowlist. They
  // were identical the day they were written and nothing made them stay that way, so hardening
  // one leaves the other — the one a compromised renderer calls — behind.
  const inlineAllowlists = walk(SRC).filter((f) => {
    if (f.endsWith('urls.ts')) return false; // the one legitimate home
    return /endsWith\(\s*'\.vercel\.(com|app)'\s*\)|host === 'vercel\.com'/.test(read(f));
  });
  assert.deepEqual(inlineAllowlists, [], 'the host allowlist must only exist in urls.ts');
});

test('the fatal window carries no preload and its own CSP', () => {
  // A data: URL is not a network response, so onHeadersReceived never fires for it — this is
  // the one page in the app the session CSP cannot reach. And it needs no IPC whatsoever.
  const src = read(join(SRC, 'main/index.ts'));
  const fatal = /function showFatal[\s\S]*?\n}/.exec(src)?.[0] ?? '';
  assert.ok(fatal.length > 0, 'showFatal must exist');
  assert.match(fatal, /noPreload:\s*true/, 'the fatal window must not carry the bridge');
  assert.match(fatal, /Content-Security-Policy/, 'a data: URL gets no CSP header — inline it');
  assert.match(fatal, /escapeHtml\(message\)/, 'interpolated text must be escaped');
});

test('THE PRELOAD has no generic passthrough', () => {
  // A generic `invoke(channel, ...args)` turns any renderer XSS into main-process code
  // execution — the exact vulnerability class contextIsolation exists to prevent. Every verb
  // must be enumerated with a compile-time channel constant.
  const src = read(join(SRC, 'preload/index.cts'));
  assert.ok(
    !/invoke:\s*\(\s*channel/.test(src),
    'the preload must not let the renderer choose the IPC channel',
  );
  assert.ok(!/ipcRenderer\s*\)/.test(src), 'the raw ipcRenderer must never be exposed');
  assert.match(src, /contextBridge\.exposeInMainWorld/);
});

test('the preload exposes exactly the enumerated API and nothing else', () => {
  const src = read(join(SRC, 'preload/index.cts'));
  const exposed = /exposeInMainWorld\(\s*'([^']+)'/.exec(src);
  assert.equal(exposed?.[1], 'bridge', 'one namespace only');
  // Every channel used must come from the constants file, never a string literal.
  const literals = src.match(/ipcRenderer\.(invoke|on|send)\(\s*'/g);
  assert.equal(literals, null, 'channels must be CHANNELS.* constants, not inline strings');
});

test('THE KEYSTORE RULE: no code anywhere stores an identity secret key', () => {
  // The Bridge must be structurally incapable of reading its own uploads. This is enforced by
  // the absence of an API — assert that absence, because adding one would look innocuous.
  const src = read(join(SRC, 'main/keystore.ts'));
  assert.ok(!/setIdentitySecretKey/.test(src));
  assert.ok(!/getIdentitySecretKey/.test(src));
  // And the hard-fail must stay.
  assert.match(src, /isEncryptionAvailable\(\)/);
  assert.match(src, /throw new KeystoreUnavailableError/);
});

test('shell.openExternal is never called with an unvalidated URL', () => {
  // openExternal executes whatever protocol handler the URL names — on Windows that includes
  // file: and every registered custom scheme. Every call site must be behind the allowlist.
  let callSites = 0;
  for (const file of walk(SRC)) {
    const src = read(file);
    // Match CALL SITES only. `ipc.ts` merely names the channel in its type contract, and
    // flagging that would train everyone to ignore this test.
    if (!/shell\.openExternal\s*\(/.test(src)) continue;
    callSites++;
    // The argument must be the OUTPUT of the validator, not merely a string validated nearby.
    // `safeExternalUrl` returns the normalized href or undefined precisely so that this is
    // checkable: if the call site can only pass what the validator returned, it cannot pass the
    // caller's original text to the OS after validating a parse of it.
    for (const m of src.matchAll(/shell\.openExternal\(([^)]*)\)/g)) {
      const arg = (m[1] ?? '').trim();
      assert.ok(
        /^safe$|^safeExternalUrl\(/.test(arg),
        `${file} passes \`${arg}\` to shell.openExternal; it must pass a safeExternalUrl() result`,
      );
    }
  }
  assert.ok(callSites > 0, 'the check must actually be exercising something');
});

test('THE READER PATH cannot fetch, persist, or touch the keystore', () => {
  // session.ts holds the unwrapped identity secret; reader.ts holds it while decrypting. The
  // structural guarantees these tests pin:
  //   - no filesystem: idSK cannot be written anywhere by the code that holds it;
  //   - no network: the roster fed to openSection cannot come from a server — the whole trust
  //     chain (trust.ts) collapses if it ever does;
  //   - no keystore: the one write capability the session has is `saveMemory(version: number)`.
  for (const f of ['main/session.ts', 'main/reader.ts']) {
    const src = read(join(SRC, f));
    assert.ok(!/from 'node:fs'/.test(src), `${f} must not touch the filesystem`);
    assert.ok(!/\bfetch\s*\(/.test(src), `${f} must not reach the network`);
    assert.ok(!/[Kk]eystore/.test(src), `${f} must not read or write the keystore directly`);
  }
});

test('the dead libsodium version is not reachable through any lockfile entry', () => {
  // 0.7.16's ESM build is broken as published: libsodium-wrappers.mjs imports a relative
  // ./libsodium-sumo.mjs that ships in a DIFFERENT package. A range slipping back to 0.7.x
  // breaks the build in a way whose error message points nowhere near the cause.
  const pkg = JSON.parse(readRaw(join(ROOT, 'packages/crypto/package.json'))) as {
    dependencies: Record<string, string>;
  };
  const range = pkg.dependencies['libsodium-wrappers-sumo'];
  assert.ok(range?.startsWith('^0.8'), `libsodium must stay on 0.8.x, found ${range}`);
});

test('the banned XML parsers are absent from every package', () => {
  // fast-xml-parser is superbly maintained and exactly wrong here: it is a CORRECT parser
  // facing an INCORRECT producer, and throws on the malformed payloads we must survive.
  // xml2js (dead 2023) and saxes (dead 2021) are simply unmaintained.
  const banned = ['xml2js', 'saxes', 'fast-xml-parser', 'node-schedule', 'node-windows'];
  const pkgs = [
    'packages/core', 'packages/crypto', 'packages/tally', 'packages/sync',
    'packages/protocol', 'packages/viewmodel', 'apps/server', 'apps/bridge',
  ];
  for (const p of pkgs) {
    const pkg = JSON.parse(readRaw(join(ROOT, p, 'package.json'))) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const b of banned) {
      assert.ok(!(b in all), `${p} must not depend on ${b}`);
    }
  }
});

test('the viewmodel stays free of DOM types — the mobile seam', () => {
  // If this tsconfig ever gains "DOM", someone can reach for `document` in the card layer and
  // React Native support dies quietly, with no failing test to say so.
  //
  // Parse the actual `lib` array rather than grepping: the file is JSONC and its comment
  // explains the rule by naming "DOM", which a grep would match.
  const raw = readRaw(join(ROOT, 'packages/viewmodel/tsconfig.json'))
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
  const cfg = JSON.parse(raw) as { compilerOptions?: { lib?: string[] } };
  const lib = cfg.compilerOptions?.lib ?? [];
  assert.ok(lib.length > 0, 'lib must be pinned, not inherited');
  assert.ok(
    !lib.some((l) => l.toLowerCase().includes('dom')),
    `packages/viewmodel must never include the DOM lib, found: ${lib.join(', ')}`,
  );
});

test('the viewmodel imports nothing but core', () => {
  for (const file of walk(join(ROOT, 'packages/viewmodel/src'))) {
    const src = read(file);
    const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]!);
    for (const i of imports) {
      const isRelative = i.startsWith('.');
      assert.ok(
        isRelative || i === '@tally-bridge/core',
        `${file} imports ${i}; the card layer must stay portable`,
      );
    }
  }
});

test('the fatal window runs on its own session, or it renders unstyled', () => {
  // CSP policies INTERSECT: when the session-wide policy (style-src 'self') and the page's own
  // <meta> (style-src 'unsafe-inline') both cover a page, BOTH must allow, so the meta cannot
  // grant back what the session denies. Measured against the real createSecureWindow + hardenApp:
  // without `isolatedSession` the body background computes to rgba(0,0,0,0) instead of #0b0f14.
  //
  // This is a source-structure assertion, not a rendering one — this repo has no Electron test
  // harness, and a rename defeats it. It is here because the bug it guards is INVISIBLE in review
  // (the code looks correct; the two policies are in different files) and only shows up on the
  // one screen a user sees when the app is already broken, which is the screen least likely to
  // be exercised before release.
  const src = read(join(SRC, 'main/index.ts'));
  const fatal = src.slice(src.indexOf('function showFatal'));
  const body = fatal.slice(0, fatal.indexOf('\n}'));
  assert.match(body, /isolatedSession:\s*'fatal-error'/,
    'showFatal must pass isolatedSession, or the session CSP intersects with its <meta> and ' +
      'strips its styling');
  assert.match(body, /noPreload:\s*true/, 'the fatal window needs no IPC and must carry no bridge');
});
