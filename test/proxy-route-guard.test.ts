import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';

// SSRF route guard — exercised through the HTTP proxy endpoint with the
// private/loopback/metadata guard ENABLED. Unlike test/proxy.test.ts (which sets
// PROXY_ALLOW_PRIVATE=true to point at a loopback mock), this file deliberately
// does NOT enable PROXY_ALLOW_PRIVATE, so precheckProxyTarget()'s isPrivateHost
// gate fires and a private target is rejected with 403 forbidden_target BEFORE a
// use is charged. Env must be settled before src/env.ts first loads, so helpers
// (which transitively import env) are imported dynamically in beforeAll — same
// isolation pattern as proxy.test.ts, except here we leave PROXY_ALLOW_PRIVATE
// unset.

let app: FastifyInstance;
let h: typeof import('./helpers.js');
let dbSql: typeof import('../src/db/index.js').sql;
const savedAllowPrivate = process.env.PROXY_ALLOW_PRIVATE;

beforeAll(async () => {
  // Make sure the SSRF guard is active for this file regardless of ambient env.
  delete process.env.PROXY_ALLOW_PRIVATE;
  h = await import('./helpers.js');
  dbSql = (await import('../src/db/index.js')).sql;
  app = await h.makeApp();
});

afterAll(async () => {
  await app?.close();
  if (savedAllowPrivate === undefined) delete process.env.PROXY_ALLOW_PRIVATE;
  else process.env.PROXY_ALLOW_PRIVATE = savedAllowPrivate;
});

beforeEach(async () => {
  await h.resetDb();
});

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

describe('proxy SSRF route guard (PROXY_ALLOW_PRIVATE disabled)', () => {
  it('rejects a metadata/loopback target with 403 forbidden_target and does NOT burn a maxUses slot', async () => {
    const { token } = await h.registerAndLogin(app);
    const pp = await h.createPassport(app, token);
    // Cloud-metadata IP — the canonical SSRF target. maxUses:1 so we can prove the
    // single slot survives a rejected call.
    const cred = await h.deposit(app, token, pp, {
      target: 'http://169.254.169.254',
      label: 'ssrf-metadata',
      type: 'api_key',
      secret: 's3cr3t',
      maxUses: 1,
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);

    const first = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/latest/meta-data' });
    expect(first.statusCode).toBe(403);
    expect(first.json().error.code).toBe('forbidden_target');

    // The guard fires BEFORE the use is charged, so the maxUses:1 slot is intact.
    const rows = await dbSql.unsafe<{ use_count: number }[]>(
      `SELECT use_count FROM credentials WHERE id = '${cred.id}'`,
    );
    expect(Number(rows[0]?.use_count ?? -1)).toBe(0);

    // A second identical SSRF call is STILL 403 forbidden_target — not 429
    // use_limit_reached — proving the rejection never consumed the one allowed use.
    const second = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/latest/meta-data' });
    expect(second.statusCode).toBe(403);
    expect(second.json().error.code).toBe('forbidden_target');
  });

  it('rejects a private RFC1918 target with 403 forbidden_target', async () => {
    const { token } = await h.registerAndLogin(app);
    const pp = await h.createPassport(app, token);
    const cred = await h.deposit(app, token, pp, {
      target: 'http://10.0.0.1',
      label: 'ssrf-private',
      type: 'api_key',
      secret: 's3cr3t',
    });
    const agent = await h.issueAgent(app, token, pp, ['vault:proxy', 'target:*']);

    const res = await proxy(agent.apiKey, cred.id, { method: 'GET', path: '/' });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('forbidden_target');
  });
});
