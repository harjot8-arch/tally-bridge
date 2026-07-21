// Root `prepare` hook: build the shared workspace packages so a fresh clone can run — but ONLY
// when they are not already built.
//
// WHY THE GUARD MATTERS
//
// `prepare` runs on every `npm install`, including the production-only install electron-builder
// performs while packaging (`npm install --omit=dev`). That install PRUNES devDependencies —
// TypeScript among them — so an unconditional `tsc` here fails with "tsc not found" and takes
// the whole installer build down. By the time electron-builder runs, the packages are already
// compiled (CI built them in an earlier step), so the correct action is to do nothing.
//
// On a genuine fresh clone the dist files are absent and devDependencies are present, so this
// builds normally. Idempotent either way.

import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Dependency order: core first (crypto's tsc needs its .d.ts), sync last.
const ORDER = ['core', 'crypto', 'protocol', 'tally', 'viewmodel', 'sync'];

const missing = ORDER.filter((p) => !existsSync(join(REPO, 'packages', p, 'dist', 'index.js')));

if (missing.length === 0) {
  console.log('[prepare] all package dist present — skipping build');
  process.exit(0);
}

console.log(`[prepare] building packages (missing: ${missing.join(', ')})`);
for (const p of ORDER) {
  execSync(`npm run build -w @tally-bridge/${p}`, { cwd: REPO, stdio: 'inherit' });
}
