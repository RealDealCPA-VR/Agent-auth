import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';

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
const saved = process.env.PROXY_ALLOW_PRIVATE;

beforeAll(async () => {
  process.env.PROXY_ALLOW_PRIVATE = 'true';
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
  app = await h.makeApp();
});

afterAll(async () => {
  await app?.close();
  await new Promise<void>((r) => server.close(() => r()));
  if (saved === undefined) delete process.env.PROXY_ALLOW_PRIVATE;
  else process.env.PROXY_ALLOW_PRIVATE = saved;
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
});
