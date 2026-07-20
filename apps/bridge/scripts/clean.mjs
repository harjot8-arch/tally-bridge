// Remove `dist/` before a build.
//
// Not hygiene — correctness. `tsc` overwrites its own outputs but never deletes ones it no
// longer emits, and `electron-builder.yml` ships `files: dist/**/*`, i.e. whatever is sitting
// there. Renaming `preload/index.ts` to `preload/index.cts` left a stale `preload/index.js`
// (the old, broken, ESM preload) in `dist` that a packaged build would have happily shipped.
//
// `rm -rf` is not portable to the Windows box this app actually targets; `fs.rmSync` is.
// Scoped to this package's own `dist` and nothing else.

import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = resolve(fileURLToPath(import.meta.url), '../../dist');
rmSync(dist, { recursive: true, force: true });
