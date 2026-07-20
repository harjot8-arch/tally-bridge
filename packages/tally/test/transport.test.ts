import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { TallyTransport, describeFailure } from '../src/transport.ts';
import { probeRequest } from '../src/requests.ts';

/**
 * A stand-in for Tally.
 *
 * The real Tally cannot be scripted into its interesting failure modes on demand — you cannot
 * ask it to return an empty body, or to hang, or to answer in UTF-16 without a BOM. So the
 * state machine is tested against a fake that can. This does NOT substitute for Spike A, which
 * answers a different question: whether our TDL is correct. This answers whether our transport
 * behaves when Tally misbehaves.
 */
async function withFakeTally(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
  fn: (port: number) => Promise<void>,
): Promise<void> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(port);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

test('a normal response succeeds', async () => {
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/xml;charset=utf-16' });
      res.end(Buffer.from('<ENVELOPE><F01>Acme</F01><F02>guid-1</F02></ENVELOPE>', 'utf16le'));
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf16le' });
      const res = await t.request(probeRequest());
      assert.ok(res.ok);
      assert.match(res.xml, /Acme/);
    },
  );
});

test('an empty body means "no company open", not an error', async () => {
  // Verified Tally behaviour, and the single most common non-happy state: the owner has
  // launched Tally but not opened their books yet.
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200);
      res.end();
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf16le' });
      const res = await t.request(probeRequest());
      assert.ok(!res.ok);
      assert.equal(res.failure.kind, 'no_company_open');
      assert.equal(describeFailure(res.failure), 'Tally is open, but no company is loaded.');
    },
  );
});

test('a non-Tally server on the port is a distinct, hard error', async () => {
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!DOCTYPE html><html><body>Some other app</body></html>');
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest());
      assert.ok(!res.ok);
      assert.equal(res.failure.kind, 'not_tally');
      assert.match(describeFailure(res.failure), /Another program is using port 9000/);
    },
  );
});

test('nothing listening means "Tally is not running" — a silent no-op, not a failure', async () => {
  // Port 1 is reserved and never listening. This is the normal overnight state and must not
  // produce noise.
  const t = new TallyTransport({ port: 1 });
  const res = await t.request(probeRequest());
  assert.ok(!res.ok);
  assert.equal(res.failure.kind, 'not_running');
  assert.equal(describeFailure(res.failure), 'Tally is not open on this computer.');
});

test('a Tally fault is surfaced verbatim', async () => {
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200);
      res.end('<ENVELOPE><LINEERROR>Unknown method $Nonsense</LINEERROR></ENVELOPE>');
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest());
      assert.ok(!res.ok);
      assert.equal(res.failure.kind, 'tally_error');
      assert.match(describeFailure(res.failure), /Unknown method \$Nonsense/);
    },
  );
});

test('a hung Tally times out and does not leak the socket', async () => {
  let sockets = 0;
  await withFakeTally(
    (_req, _res) => {
      sockets++;
      // Never respond. This is Tally blocked on a modal dialog the owner left open.
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest(), 300);
      assert.ok(!res.ok);
      assert.equal(res.failure.kind, 'timeout');
      assert.match(describeFailure(res.failure), /did not respond in time/);
      assert.equal(sockets, 1);
    },
  );
});

test('a non-200 status is reported as such', async () => {
  await withFakeTally(
    (_req, res) => {
      res.writeHead(500);
      res.end('boom');
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest());
      assert.ok(!res.ok);
      assert.equal(res.failure.kind, 'http_status');
    },
  );
});

test('THE concurrency rule: requests are strictly serialized', async () => {
  // Tally's listener is embedded in a single-threaded desktop app the owner is typing into.
  // Concurrent requests cause hangs. If this ever regresses, it will present as intermittent
  // corruption in the field and be miserable to diagnose — so assert it directly.
  let inFlight = 0;
  let maxInFlight = 0;

  await withFakeTally(
    (_req, res) => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      setTimeout(() => {
        inFlight--;
        res.writeHead(200);
        res.end('<ENVELOPE><F01>x</F01></ENVELOPE>');
      }, 40);
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      await Promise.all([
        t.request(probeRequest()),
        t.request(probeRequest()),
        t.request(probeRequest()),
        t.request(probeRequest()),
        t.request(probeRequest()),
      ]);
      assert.equal(maxInFlight, 1, 'Tally must never see two overlapping requests');
    },
  );
});

test('a failing request does not poison the queue', async () => {
  let n = 0;
  await withFakeTally(
    (_req, res) => {
      n++;
      if (n === 1) {
        res.writeHead(500);
        res.end();
      } else {
        res.writeHead(200);
        res.end('<ENVELOPE><F01>recovered</F01></ENVELOPE>');
      }
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const first = await t.request(probeRequest());
      assert.ok(!first.ok);
      // The mutex chains on settlement; a rejection must not stall every later request.
      const second = await t.request(probeRequest());
      assert.ok(second.ok);
      assert.match(second.xml, /recovered/);
    },
  );
});

test('encoding detection settles on UTF-16LE when Tally accepts it', async () => {
  await withFakeTally(
    (req, res) => {
      // Accept only UTF-16 requests, as production Tally reportedly does.
      const ct = req.headers['content-type'] ?? '';
      if (!ct.includes('utf-16')) {
        res.writeHead(200);
        res.end();
        return;
      }
      res.writeHead(200);
      res.end(Buffer.from('<ENVELOPE><F01>ok</F01></ENVELOPE>', 'utf16le'));
    },
    async (port) => {
      const t = new TallyTransport({ port });
      assert.equal(await t.detectEncoding(probeRequest()), 'utf16le');
      assert.equal(t.currentEncoding, 'utf16le');
    },
  );
});

test('encoding detection falls back to UTF-8 when UTF-16 is rejected', async () => {
  await withFakeTally(
    (req, res) => {
      const ct = req.headers['content-type'] ?? '';
      if (!ct.includes('utf-8')) {
        // Empty body: looks like "no company open", which is the ambiguous signal that
        // justifies trying the other encoding.
        res.writeHead(200);
        res.end();
        return;
      }
      res.writeHead(200);
      res.end('<ENVELOPE><F01>ok</F01></ENVELOPE>');
    },
    async (port) => {
      const t = new TallyTransport({ port });
      assert.equal(await t.detectEncoding(probeRequest()), 'utf8');
    },
  );
});

test('encoding detection gives up immediately when Tally is closed', async () => {
  // Retrying in UTF-8 against a closed Tally tells us nothing and just doubles the wait.
  const t = new TallyTransport({ port: 1 });
  assert.equal(await t.detectEncoding(probeRequest()), undefined);
});

test('the request sent is well-formed XML that we generated', async () => {
  await withFakeTally(
    (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        assert.match(body, /<TALLYREQUEST>Export<\/TALLYREQUEST>/);
        assert.match(body, /<XMLTAG>F01<\/XMLTAG>/);
        assert.match(body, /<TYPE>Company<\/TYPE>/);
        // We must never ask for a built-in report.
        assert.doesNotMatch(body, /<ID>Balance Sheet<\/ID>/);
        res.writeHead(200);
        res.end('<ENVELOPE><F01>x</F01></ENVELOPE>');
      });
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest());
      assert.ok(res.ok);
    },
  );
});

test('a response body is capped, so a hostile or broken :9000 cannot exhaust memory', async () => {
  // There was NO size cap. Every chunk was pushed into an array and concatenated at 'end', so
  // whatever is on port 9000 chose how much of this machine's memory to consume — and it is a
  // port with no authentication, on a desktop the owner also browses the web from. Tally's own
  // answers to these deliberately narrow requests are kilobytes; a full sync is under 100KB.
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/xml' });
      // Never ends. Streams far past the cap.
      const chunk = Buffer.alloc(1 << 20, 0x41);
      const pump = () => {
        while (res.write(chunk)) {
          /* fill the socket buffer, then wait for drain */
        }
      };
      res.on('drain', pump);
      pump();
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest(), 30_000);
      assert.ok(!res.ok, 'an oversized body must not be accepted');
      assert.equal(res.failure.kind, 'not_tally');
      // And it must be REFUSED, not merely timed out — the cap has to fire long before the
      // 60s section deadline, or the memory is already gone by the time we notice.
      assert.notEqual(res.failure.kind, 'timeout');
    },
  );
});

test('the size cap does not fire on a normal chunked response', async () => {
  await withFakeTally(
    (_req, res) => {
      res.writeHead(200);
      res.write('<ENVELOPE>');
      res.write('<F01>Acme</F01>');
      res.end('</ENVELOPE>');
    },
    async (port) => {
      const t = new TallyTransport({ port, encoding: 'utf8' });
      const res = await t.request(probeRequest());
      assert.ok(res.ok);
      assert.match(res.xml, /Acme/);
    },
  );
});
