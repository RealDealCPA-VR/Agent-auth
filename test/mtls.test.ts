import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { X509Certificate } from 'node:crypto';
import selfsigned from 'selfsigned';
import type { FastifyInstance } from 'fastify';

/**
 * mTLS agent identity — proxy-terminated path (deterministic, no real TLS).
 *
 * We exercise the trusted-proxy mode: the env is configured for mTLS with a
 * trusted proxy BEFORE buildServer / env are imported (env is read once at module
 * load, like test/jwt-rotation.test.ts), then the fingerprint is forwarded via
 * the configured header on plain inject() requests. The native-TLS handshake path
 * is covered structurally by fingerprintFromPem + the bind flow.
 */

// Must be set before any import that transitively loads src/env.ts.
const saved: Record<string, string | undefined> = {};
for (const k of ['MTLS_ENABLED', 'MTLS_TRUSTED_PROXY', 'MTLS_FP_HEADER']) saved[k] = process.env[k];
process.env.MTLS_ENABLED = 'true';
process.env.MTLS_TRUSTED_PROXY = 'true';
// Use the default header name explicitly so the test documents the wire contract.
process.env.MTLS_FP_HEADER = 'x-client-cert-fingerprint';
const FP_HEADER = 'x-client-cert-fingerprint';

type Helpers = typeof import('./helpers.js');
type Mtls = typeof import('../src/auth/mtls.js');

let app: FastifyInstance;
let h: Helpers;
let mtls: Mtls;

beforeAll(async () => {
  // Import AFTER env is set so the env loader sees the mTLS proxy config.
  h = await import('./helpers.js');
  mtls = await import('../src/auth/mtls.js');
  app = await h.makeApp();
});

afterAll(async () => {
  await app?.close();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

beforeEach(async () => {
  await h.resetDb();
});

const SECRET = 'ghp_supersecrettoken_mtls';
const HEX64 = 'a'.repeat(64);

/** Human + passport + one github.com credential + an agent (no API key needed). */
async function setup() {
  const { token } = await h.registerAndLogin(app);
  const passportId = await h.createPassport(app, token, 'vault');
  const cred = await h.deposit(app, token, passportId, {
    target: 'github.com',
    label: 'gh login',
    type: 'password',
    secret: SECRET,
  });
  const agent = await h.issueAgent(app, token, passportId, ['vault:read', 'vault:use', 'target:*']);
  return { token, passportId, credId: cred.id, agentId: agent.id };
}

async function bind(token: string, agentId: string, body: Record<string, unknown>) {
  return app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/mtls`,
    headers: h.auth(token),
    payload: body,
  });
}

describe('mTLS agent identity (proxy-terminated)', () => {
  it('authenticates an agent via the forwarded fingerprint header (no bearer)', async () => {
    const { token, agentId, credId } = await setup();

    const bound = await bind(token, agentId, { fingerprint: HEX64 });
    expect(bound.statusCode).toBe(200);
    expect(bound.json().certFingerprint).toBe(HEX64);

    // No Authorization header — authenticate purely by the proxy-forwarded fp.
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: HEX64 },
    });
    expect(list.statusCode).toBe(200);
    const body = list.json();
    expect(body.pagination.total).toBe(1);
    expect(body.items[0].id).toBe(credId);
    expect(body.items[0].target).toBe('github.com');
  });

  it('normalizes a colon-delimited / uppercase fingerprint header', async () => {
    const { token, agentId } = await setup();
    await bind(token, agentId, { fingerprint: HEX64 });

    // Same fingerprint, presented as uppercase with colons (a common proxy format).
    const upper = HEX64.toUpperCase().match(/../g)!.join(':');
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: upper },
    });
    expect(list.statusCode).toBe(200);
    expect(list.json().pagination.total).toBe(1);
  });

  it('rejects an unknown fingerprint with 401', async () => {
    await setup();
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: 'b'.repeat(64) },
    });
    expect(list.statusCode).toBe(401);
    expect(list.json().error.code).toBe('unauthorized');
  });

  it('still serves 401 with no bearer and no fingerprint header', async () => {
    await setup();
    const list = await app.inject({ method: 'GET', url: '/v1/vault/credentials' });
    expect(list.statusCode).toBe(401);
    expect(list.json().error.code).toBe('unauthorized');
  });

  it('fails closed once the mTLS-bound agent is revoked', async () => {
    const { token, agentId } = await setup();
    await bind(token, agentId, { fingerprint: HEX64 });

    const revoke = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agentId}/revoke`,
      headers: h.auth(token),
    });
    expect(revoke.statusCode).toBe(200);

    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: HEX64 },
    });
    expect(list.statusCode).toBe(401);
  });
});

describe('mTLS binding (issuance)', () => {
  it('requires ownership of the agent (other principal -> 404)', async () => {
    const { agentId } = await setup();
    // A different human cannot bind a cert to someone else's agent.
    const other = await h.registerAndLogin(app);
    const res = await bind(other.token, agentId, { fingerprint: HEX64 });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it('rejects a bind with neither certPem nor fingerprint (400)', async () => {
    const { token, agentId } = await setup();
    const res = await bind(token, agentId, {});
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('rejects a malformed fingerprint (400)', async () => {
    const { token, agentId } = await setup();
    const res = await bind(token, agentId, { fingerprint: 'not-a-fingerprint' });
    expect(res.statusCode).toBe(400);
  });

  it('rejects an invalid certPem (not an X.509 cert) with 400 invalid_request', async () => {
    const { token, agentId } = await setup();
    const res = await bind(token, agentId, { certPem: 'not-a-cert' });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
    expect(res.json().error.message).toContain('X.509');
  });

  it('binding a fingerprint already bound to another agent returns 409, not 500', async () => {
    const { token, passportId, agentId } = await setup();
    const first = await bind(token, agentId, { fingerprint: HEX64 });
    expect(first.statusCode).toBe(200);
    const other = await h.issueAgent(app, token, passportId, ['vault:use', 'target:*']);
    const res = await bind(token, other.id, { fingerprint: HEX64 });
    expect(res.statusCode).toBe(409);
    expect(res.json().error.code).toBe('conflict');
  });

  it('derives the fingerprint from a PEM cert matching node:crypto', async () => {
    const { token, agentId } = await setup();
    const pems = selfsigned.generate([{ name: 'commonName', value: 'agent.test' }], { days: 1 });

    const expected = new X509Certificate(pems.cert).fingerprint256.replace(/:/g, '').toLowerCase();
    expect(mtls.fingerprintFromPem(pems.cert)).toBe(expected);

    const res = await bind(token, agentId, { certPem: pems.cert });
    expect(res.statusCode).toBe(200);
    expect(res.json().certFingerprint).toBe(expected);

    // And the derived fingerprint authenticates the agent over the proxy header.
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: { [FP_HEADER]: expected },
    });
    expect(list.statusCode).toBe(200);
    expect(list.json().pagination.total).toBe(1);
  });
});
