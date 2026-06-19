import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
// NOTE: do NOT statically import anything that loads src/env.js here — env must be
// set (PROXY_ALLOW_PRIVATE) before the env module first loads. proxyRequest is
// imported dynamically in beforeAll for the same reason as the helpers.
type ProxyRequestFn = typeof import('../src/lib/proxy.js').proxyRequest;

// Proxy mode injects credentials server-side and pins the host to the target, so
// we point the credential at a local mock downstream and assert (a) the injected
// auth reached the downstream, (b) the agent can't override it, (c) the raw
// secret is redacted from what the agent sees. Loopback target needs the SSRF
// guard relaxed — set before the env module loads (dynamic import in beforeAll).

const SECRET = 's3cr3t-PROXY-value';
const downstream = { lastAuth: null as string | null, lastCookie: null as string | null };
let server: http.Server;
let port = 0;
let app: FastifyInstance;
let h: typeof import('./helpers.js');
let proxyRequest: ProxyRequestFn;
let dbSql: typeof import('../src/db/index.js').sql;
let closedPort = 0; // a port that is bound then closed → connections are refused
const saved = process.env.PROXY_ALLOW_PRIVATE;

const savedTimeout = process.env.PROXY_TIMEOUT_MS;
beforeAll(async () => {
  process.env.PROXY_ALLOW_PRIVATE = 'true';
  process.env.PROXY_TIMEOUT_MS = '500'; // so the /slow route times out quickly
  server = http.createServer((req, res) => {
    downstream.lastAuth = req.headers.authorization ?? null;
    downstream.lastCookie = req.headers.cookie ?? null;
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString();
      const url = req.url ?? '/';
      if (url.startsWith('/whoami')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ authSeen: req.headers.authorization ?? null, ok: true }));
      } else if (url.startsWith('/echo')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ method: req.method, url, body }));
      } else if (url.startsWith('/reflect')) {
        // A hostile/echoing downstream that reflects the injected secret back in
        // response headers (Set-Cookie + an echoed auth header).
        res.writeHead(200, {
          'content-type': 'application/json',
          'set-cookie': `session=${req.headers.authorization ?? ''}`,
          'x-echo-auth': req.headers.authorization ?? '',
          'x-echo-cookie': req.headers.cookie ?? '',
        });
        res.end(JSON.stringify({ ok: true }));
      } else if (url.startsWith('/hdrname')) {
        // Reflect the injected cookie value into a response header NAME.
        const c = (req.headers.cookie ?? 'none').replace(/[^a-z0-9-]/gi, '') || 'none';
        res.writeHead(200, { 'content-type': 'application/json', [`x-saw-${c}`]: '1' });
        res.end(JSON.stringify({ ok: true }));
      } else if (url.startsWith('/slow')) {
        // Connect succeeds + request is received, but the response is delayed past
        // PROXY_TIMEOUT_MS → a response-phase timeout (delivered=true).
        setTimeout(() => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        }, 2000);
      } else if (url.startsWith('/redirect')) {
        res.writeHead(302, { location: 'http://evil.example/' });
        res.end();
      } else {
        res.writeHead(404);
        res.end('not found');
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
  h = await import('./helpers.js');
  proxyRequest = (await import('../src/lib/proxy.js')).proxyRequest;
  dbSql = (await import('../src/db/index.js')).sql;
  app = await h.makeApp();
  // Bind then immediately close a port so connections to it are refused.
  const tmp = http.createServer();
  await new Promise<void>((r) => tmp.listen(0, '127.0.0.1', r));
  closedPort = (tmp.address() as AddressInfo).port;
  await new Promise<void>((r) => tmp.close(() => r()));
});

afterAll(async () => {
  await app?.close();
  await new Promise<void>((r) => server.close(() => r()));
  if (saved === undefined) delete process.env.PROXY_ALLOW_PRIVATE;
  else process.env.PROXY_ALLOW_PRIVATE = saved;
  if (savedTimeout === undefined) delete process.env.PROXY_TIMEOUT_MS;
  else process.env.PROXY_TIMEOUT_MS = savedTimeout;
});

beforeEach(async () => {
  await h.resetDb();
});

async function setup(opts: { scopes?: string[]; injection?: unknown; type?: string } = {}) {
  const { token } = await h.registerAndLogin(app);
  const pp = await h.createPassport(app, token);
  const cred = await h.deposit(app, token, pp, {
    target: `http://localhost:${port}`,
    label: 'svc',
    type: opts.type ?? 'api_key',
    secret: SECRET,
    ...(opts.injection ? { injection: opts.injection } : {}),
  });
  const agent = await h.issueAgent(app, token, pp, opts.scopes ?? ['vault:proxy', 'target:*']);
  return { token, pp, credId: cred.id, apiKey: agent.apiKey };
}

function proxy(
  apiKey: string,
  id: string,
  body: Record<string, unknown>,
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: 'POST',
    url: `/v1/vault/credentials/${id}/proxy`,
    headers: h.auth(apiKey),
    payload: body,
  });
}

describe('proxy mode', () => {
  it('injects the credential server-side and redacts it from the agent response', async () => {
    const { apiKey, credId } = await setup();
    const res = await proxy(apiKey, credId, { method: 'GET', path: '/whoami' });
    expect(res.statusCode).toBe(200);
    // The downstream actually received the injected bearer token...
    expect(downstream.lastAuth).toBe(`Bearer ${SECRET}`);
    // ...but the agent never sees the raw secret (redacted in the returned body).
    const body = res.json();
    expect(body.status).toBe(200);
    expect(JSON.stringify(body)).not.toContain(SECRET);
    expect(JSON.stringify(body)).toContain('[redacted]');
  });

  it('an agent cannot override the injected auth header', async () => {
    const { apiKey, credId } = await setup();
    await proxy(apiKey, credId, {
      method: 'GET',
      path: '/whoami',
      headers: { authorization: 'Bearer EVIL' },
    });
    expect(downstream.lastAuth).toBe(`Bearer ${SECRET}`); // server wins
  });

  it('honors a custom header injection (name + prefix)', async () => {
    const { apiKey, credId } = await setup({
      injection: { mode: 'header', name: 'authorization', prefix: 'token ' },
    });
    await proxy(apiKey, credId, { method: 'GET', path: '/whoami' });
    expect(downstream.lastAuth).toBe(`token ${SECRET}`);
  });

  it('injects a cookie credential', async () => {
    const { apiKey, credId } = await setup({ type: 'cookie' });
    await proxy(apiKey, credId, { method: 'GET', path: '/whoami' });
    expect(downstream.lastCookie).toBe(SECRET);
  });

  it('forwards method and body to the downstream', async () => {
    const { apiKey, credId } = await setup();
    const res = await proxy(apiKey, credId, { method: 'POST', path: '/echo', body: 'hello-body' });
    expect(res.json().body).toBe('{"method":"POST","url":"/echo","body":"hello-body"}');
  });

  it('redacts the secret from REFLECTED response headers (Set-Cookie / echoed header)', async () => {
    const { apiKey, credId } = await setup();
    const res = await proxy(apiKey, credId, { method: 'GET', path: '/reflect' });
    expect(res.statusCode).toBe(200);
    // The whole response the agent receives — headers included — must not carry
    // the raw secret, even though the downstream reflected it back.
    const blob = JSON.stringify(res.json());
    expect(blob).not.toContain(SECRET);
    expect(blob).toContain('[redacted]');
    // And specifically the response headers are scrubbed.
    const headers = res.json().headers as Record<string, string>;
    expect(JSON.stringify(headers)).not.toContain(SECRET);
    expect(headers['x-echo-auth']).toContain('[redacted]');
  });

  it('does NOT follow redirects (returns the 3xx as-is)', async () => {
    const { apiKey, credId } = await setup();
    const res = await proxy(apiKey, credId, { method: 'GET', path: '/redirect' });
    expect(res.json().status).toBe(302);
  });

  it('requires the vault:proxy scope (vault:use alone is rejected)', async () => {
    const { apiKey, credId } = await setup({ scopes: ['vault:use', 'target:*'] });
    const res = await proxy(apiKey, credId, { method: 'GET', path: '/whoami' });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.message).toContain('vault:proxy');
  });

  it('enforces target-scoping', async () => {
    const { apiKey, credId } = await setup({ scopes: ['vault:proxy', 'target:other.example'] });
    const res = await proxy(apiKey, credId, { method: 'GET', path: '/whoami' });
    expect(res.statusCode).toBe(403);
  });

  it('rejects a path that does not start with /', async () => {
    const { apiKey, credId } = await setup();
    const res = await proxy(apiKey, credId, { method: 'GET', path: 'whoami' });
    expect(res.statusCode).toBe(400);
  });

  it('returns 404 (not 500) when the credential id is not a UUID', async () => {
    const { apiKey } = await setup();
    const res = await proxy(apiKey, 'not-a-uuid', { method: 'GET', path: '/whoami' });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it('lets a proxy-only agent (no vault:read) list metadata to resolve a target', async () => {
    // proxy-only agents must be able to resolve a target host -> credential id
    // even though they can never read the secret.
    const { apiKey } = await setup({ scopes: ['vault:proxy', 'target:*'] });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: h.auth(apiKey),
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().items.length).toBeGreaterThan(0);
  });

  it('redacts a query-mode secret with special chars (! ( ) ~ space) when the URL is reflected', async () => {
    const { token, pp } = await setup();
    const special = "sk-live-A!B(C)D~E withspace";
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${port}`,
      label: 'q',
      type: 'api_key',
      secret: special,
      injection: { mode: 'query', name: 'api_key' },
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);
    // /echo reflects req.url (which carries the injected ?api_key=<secret>) back.
    const res = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/echo' });
    expect(res.statusCode).toBe(200);
    const blob = JSON.stringify(res.json());
    // Neither the raw secret nor its exact on-wire (form-encoded) bytes may leak.
    const wire = new URLSearchParams([['k', special]]).toString().slice(2);
    expect(blob).not.toContain(special);
    expect(blob).not.toContain(wire);
    expect(blob).toContain('[redacted]');
  });

  it('redacts the secret from a reflected response header NAME, not just the value', async () => {
    const { token, pp } = await setup();
    const tok = 'simpletoken-abc123'; // header-name-safe
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${port}`,
      label: 'c',
      type: 'cookie',
      secret: tok,
      injection: { mode: 'cookie' },
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);
    const res = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/hdrname' });
    expect(res.statusCode).toBe(200);
    const headers = res.json().headers as Record<string, string>;
    const keys = Object.keys(headers).join(',');
    expect(keys).not.toContain(tok);
    expect(keys).toContain('x-saw-[redacted]');
  });

  it('rejects a malformed agent header with 400 and does not burn a maxUses slot', async () => {
    const { token, pp } = await setup();
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${port}`,
      label: 'capped2',
      type: 'api_key',
      secret: SECRET,
      maxUses: 1,
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);
    // Invalid header name (contains a space) — rejected at the schema, before any use.
    const bad = await proxy(agent.apiKey, cred.id, {
      method: 'GET',
      path: '/whoami',
      headers: { 'x y': '1' },
    });
    expect(bad.statusCode).toBe(400);
    // The single use is intact — the malformed request never reached the client.
    const okRes = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/whoami' });
    expect(okRes.statusCode).toBe(200);
  });

  it('proxyRequest RESOLVES (never throws) on a header the HTTP client rejects', async () => {
    // Belt-and-suspenders: even if a bad header reaches proxyRequest, it returns a
    // structured outcome rather than rejecting the promise. (Loopback allowed here.)
    const outcome = await proxyRequest({
      target: `http://localhost:${port}`,
      type: 'api_key',
      injection: { mode: 'bearer' },
      secret: SECRET,
      request: { method: 'GET', path: '/whoami', headers: { 'bad\r\nname': 'x' } },
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe('bad_request');
  });

  it('refunds the maxUses slot when the downstream proxy call fails (unreachable)', async () => {
    const { token, pp, apiKey } = await setup();
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${closedPort}`,
      label: 'down',
      type: 'api_key',
      secret: SECRET,
      maxUses: 1,
    });
    const res = await proxy(apiKey, cred.id, { method: 'GET', path: '/x' });
    expect([502, 504]).toContain(res.statusCode);
    // The use was charged then released — the slot is intact.
    const rows = await dbSql.unsafe<{ use_count: number }[]>(
      `SELECT use_count FROM credentials WHERE id = '${cred.id}'`,
    );
    expect(Number(rows[0]?.use_count ?? -1)).toBe(0);
  });

  it('does NOT refund the maxUses slot on a response-phase timeout (secret already delivered)', async () => {
    const { token, pp, apiKey } = await setup();
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${port}`,
      label: 'slow',
      type: 'api_key',
      secret: SECRET,
      maxUses: 1,
    });
    // The mock connects and receives the request but responds after the timeout.
    const res = await proxy(apiKey, cred.id, { method: 'GET', path: '/slow' });
    expect(res.statusCode).toBe(504);
    // The request reached the target, so the use is consumed (at-most-once) — NOT
    // refunded; a maxUses:1 credential is now exhausted.
    const rows = await dbSql.unsafe<{ use_count: number }[]>(
      `SELECT use_count FROM credentials WHERE id = '${cred.id}'`,
    );
    expect(Number(rows[0]?.use_count ?? -1)).toBe(1);
  });

  it('refunds the approval grant when the downstream proxy call fails (no re-approval)', async () => {
    const { token, pp, apiKey } = await setup();
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${closedPort}`,
      label: 'down2',
      type: 'api_key',
      secret: SECRET,
      requireApproval: true,
    });
    // First proxy -> 202 pending; the human approves.
    const pending = await proxy(apiKey, cred.id, { method: 'GET', path: '/x' });
    expect(pending.statusCode).toBe(202);
    const approved = await app.inject({
      method: 'POST',
      url: `/v1/approvals/${pending.json().requestId}/approve`,
      headers: h.auth(token),
    });
    expect(approved.statusCode).toBe(200);
    // Grant consumed, downstream unreachable -> 502; the grant is refunded.
    expect([502, 504]).toContain((await proxy(apiKey, cred.id, { method: 'GET', path: '/x' })).statusCode);
    // Because it was refunded, a retry still has a LIVE grant — it attempts delivery
    // again (502), it does NOT fall back to 202 pending (which would mean re-approval).
    expect([502, 504]).toContain((await proxy(apiKey, cred.id, { method: 'GET', path: '/x' })).statusCode);
  });

  it('rejects a header-mode injection with a non-token name at deposit (400)', async () => {
    const { token } = await h.registerAndLogin(app);
    const pp = await h.createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${pp}/credentials`,
      headers: h.auth(token),
      payload: {
        target: 'api.test',
        label: 'x',
        type: 'api_key',
        secret: 's',
        injection: { mode: 'header', name: 'X Bad Name' },
      },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects a header-mode injection prefix containing CR/LF at deposit (400)', async () => {
    const { token } = await h.registerAndLogin(app);
    const pp = await h.createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${pp}/credentials`,
      headers: h.auth(token),
      payload: {
        target: 'api.test',
        label: 'x',
        type: 'api_key',
        secret: 's',
        injection: { mode: 'header', name: 'authorization', prefix: 'token \r\nX-Evil: 1' },
      },
    });
    expect(res.statusCode).toBe(400);
  });

  it('does NOT burn a maxUses slot when the proxy is rejected by a guard', async () => {
    const { token, pp } = await setup();
    // A fresh credential with maxUses:1 at the same mock target.
    const cred = await h.deposit(app, token, pp, {
      target: `http://localhost:${port}`,
      label: 'capped',
      type: 'api_key',
      secret: SECRET,
      maxUses: 1,
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);
    // A bad path is rejected by the precheck (before any use is charged).
    const bad = await proxy(agent.apiKey, cred.id, { method: 'GET', path: 'no-slash' });
    expect(bad.statusCode).toBe(400);
    // The single allowed use is still available — the rejected call didn't burn it.
    const okRes = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/whoami' });
    expect(okRes.statusCode).toBe(200);
  });
});
