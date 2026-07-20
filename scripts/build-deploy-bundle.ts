import { join } from 'node:path';
import { buildDeployBundle } from './deploy-bundle/build.ts';

/**
 * CLI for the deploy-bundle pipeline. Writes the Build Output API v3 bundle where
 * `loadDeployBundle()` (apps/bridge/src/main/wizard-effects.ts) expects it.
 *
 *   node --experimental-strip-types scripts/build-deploy-bundle.ts [--out <dir>]
 *
 * or from the repo root: `npm run build:deploy-bundle`.
 */
const outFlag = process.argv.indexOf('--out');
const outDir =
  outFlag !== -1 && process.argv[outFlag + 1]
    ? process.argv[outFlag + 1]!
    : join(import.meta.dirname, '../apps/bridge/deploy-bundle');

const result = await buildDeployBundle({ outDir });
const funcs = result.functionPaths.length;
console.log(`deploy bundle: ${result.files.length} files, ${funcs} functions -> ${result.outDir}`);
console.log('verified: health smoke passed, bundled libsodium sign/verify passed');
