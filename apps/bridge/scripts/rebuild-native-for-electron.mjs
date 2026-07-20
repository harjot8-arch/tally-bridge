// OPT-IN DEV SCRIPT. Nothing runs this for you — not `build`, not `test`, not `postinstall`.
// It is here so that `npm run dev` has a documented answer, and it requires `--yes` because of
// what it does to everyone else's workspace.
//
// ---------------------------------------------------------------------------------------------
// THE PROBLEM
//
// `better-sqlite3` is a native addon: a `.node` binary compiled against ONE V8 ABI. `npm install`
// builds it for the Node you have (NODE_MODULE_VERSION 127). Electron 43 embeds a different V8
// (NODE_MODULE_VERSION 148). So `new SyncStore(...)` in a dev run dies with:
//
//   Error: The module '.../better_sqlite3.node' was compiled against a different Node.js version
//   using NODE_MODULE_VERSION 127. This version of Node.js requires NODE_MODULE_VERSION 148.
//
// which `onFatalStartup` catches and turns into the "Tally Bridge cannot start" window. The app
// starts, then dies before the dashboard opens.
//
// THIS IS A DEV-ONLY PROBLEM. The packaged app is fine: `electron-builder.yml` sets
// `npmRebuild: true`, so electron-builder rebuilds native deps against Electron's ABI at package
// time, and `asarUnpack: "**/*.node"` keeps the binary loadable from outside the asar. Shipping
// is not affected by any of this.
//
// ---------------------------------------------------------------------------------------------
// WHY IT IS NOT AUTOMATIC, AND WHY YOU SHOULD THINK BEFORE RUNNING IT
//
// THE ABI IS A GLOBAL, SHARED TOGGLE. There is exactly one `node_modules/better-sqlite3/build`
// in this workspace and every package shares it. Rebuilding for Electron makes the desktop app
// run and SIMULTANEOUSLY breaks `npm test` everywhere — `node --test` is plain Node, so it will
// then fail to load the same binary with the error above, inverted (148 vs 127). You cannot have
// both at once. That is why this is a deliberate, explicit act with a documented way back:
//
//   npm run dev:rebuild-native -- --yes     # Electron ABI: the app runs, `npm test` breaks
//   npm run dev:restore-native -- --yes     # Node ABI:     `npm test` runs, the app breaks
//
// If you only need to work on the renderer, the preload, or the IPC surface, YOU DO NOT NEED
// THIS. Everything except the SQLite-backed sync store works without it.

import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(fileURLToPath(import.meta.url), '../../../..');
const toElectron = !process.argv.includes('--to-node');
const target = toElectron ? 'Electron' : 'Node';

if (!process.argv.includes('--yes')) {
  console.error(
    `\nRefusing to rebuild better-sqlite3 for ${target} without --yes.\n\n` +
      `This mutates the SHARED node_modules for every package in this workspace and will\n` +
      `break ${toElectron ? '`npm test` (plain Node cannot load an Electron-ABI binary)' : 'the Electron app (it cannot load a Node-ABI binary)'}.\n\n` +
      `  npm run ${toElectron ? 'dev:rebuild-native' : 'dev:restore-native'} -- --yes\n\n` +
      `Read the header of scripts/rebuild-native-for-electron.mjs first.\n`,
  );
  process.exit(1);
}

const args = ['rebuild', 'better-sqlite3', '--foreground-scripts'];
if (toElectron) {
  // The Electron version is read, never hardcoded: a hardcoded target silently rebuilds for the
  // wrong ABI the day someone bumps Electron, and the failure looks identical to doing nothing.
  const version = createRequire(import.meta.url)('electron/package.json').version;
  console.log(`Rebuilding better-sqlite3 against Electron ${version} (from node_modules/electron).`);
  args.push(
    '--runtime=electron',
    `--target=${version}`,
    '--dist-url=https://electronjs.org/headers',
  );
} else {
  console.log(`Rebuilding better-sqlite3 against this Node (${process.version}).`);
}

console.log(`> npm ${args.join(' ')}\n`);
const r = spawnSync('npm', args, { cwd: REPO, stdio: 'inherit' });
if (r.status !== 0) process.exit(r.status ?? 1);

console.log(
  toElectron
    ? '\nDone. `npx electron .` will now reach the dashboard. `npm test` will NOT run until you\n' +
        'run `npm run dev:restore-native -- --yes`.'
    : '\nDone. `npm test` works again.',
);
