// Executes a built .func directory's index.js the way Vercel's Node launcher would (module's
// default export called with (IncomingMessage, ServerResponse)) and demands 200 {ok:true} from
// GET /api/health. Run by build.ts; usage: node smoke.cjs <path-to-.func-dir>
'use strict';
const { Readable } = require('node:stream');
const path = require('node:path');

const funcDir = process.argv[2];
if (!funcDir) {
  console.error('usage: node smoke.cjs <func-dir>');
  process.exit(2);
}

const mod = require(path.join(funcDir, 'index.js'));
const handler = typeof mod === 'function' ? mod : mod.default;
if (typeof handler !== 'function') {
  console.error('bundle exports no callable handler (module.exports and .default are both non-functions)');
  process.exit(1);
}

const req = Readable.from([]);
req.method = 'GET';
req.url = '/api/health';
req.headers = {};

const res = {
  statusCode: 0,
  setHeader() {},
  end(body) {
    let parsed;
    try {
      parsed = JSON.parse(String(body));
    } catch {
      console.error(`health returned unparsable body: ${String(body).slice(0, 200)}`);
      process.exit(1);
    }
    if (this.statusCode === 200 && parsed.ok === true) {
      process.exit(0);
    }
    console.error(`health returned ${this.statusCode} ${String(body).slice(0, 200)}`);
    process.exit(1);
  },
};

Promise.resolve(handler(req, res)).catch((e) => {
  console.error(e);
  process.exit(1);
});

// A handler that never answers is as broken as one that errors.
setTimeout(() => {
  console.error('health smoke timed out after 10s');
  process.exit(1);
}, 10_000).unref?.();
