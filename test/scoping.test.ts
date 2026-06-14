import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { matchesTargetPattern } from '../src/auth/agent.js';
import {
  makeApp,
  resetDb,
  auth,
  registerAndLogin,
  createPassport,
  deposit,
  issueAgent,
} from './helpers.js';

describe('matchesTargetPattern (unit)', () => {
  it('exact host matches only itself', () => {
    expect(matchesTargetPattern('github.com', 'github.com')).toBe(true);
    expect(matchesTargetPattern('github.com', 'api.github.com')).toBe(false);
    expect(matchesTargetPattern('github.com', 'notgithub.com')).toBe(false);
  });

  it('full wildcard matches anything', () => {
    expect(matchesTargetPattern('*', 'anything.example.com')).toBe(true);
  });

  it('subdomain wildcard matches exactly one label', () => {
    expect(matchesTargetPattern('*.example.com', 'api.example.com')).toBe(true);
    expect(matchesTargetPattern('*.example.com', 'a.example.com')).toBe(true);
  });

  it('subdomain wildcard does NOT match the apex', () => {
    expect(matchesTargetPattern('*.example.com', 'example.com')).toBe(false);
  });

  it('subdomain wildcard does NOT match deeper subdomains', () => {
    expect(matchesTargetPattern('*.example.com', 'a.b.example.com')).toBe(false);
  });

  it('subdomain wildcard does NOT match look-alike suffixes (no dot bypass)', () => {
    expect(matchesTargetPattern('*.example.com', 'notexample.com')).toBe(false);
    expect(matchesTargetPattern('*.example.com', 'xexample.com')).toBe(false);
    expect(matchesTargetPattern('*.example.com', 'evil-example.com')).toBe(false);
  });

  it('matches case-insensitively (hostnames are case-insensitive)', () => {
    expect(matchesTargetPattern('github.com', 'GitHub.COM')).toBe(true);
    expect(matchesTargetPattern('*.example.com', 'API.Example.com')).toBe(true);
    expect(matchesTargetPattern('*.Example.com', 'api.example.com')).toBe(true);
  });
});

describe('target scoping + expiry (integration)', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    app = await makeApp();
  });
  afterAll(async () => {
    await app.close();
  });
  beforeEach(async () => {
    await resetDb();
  });

  it('subdomain-scoped agent sees and uses only the single-label subdomain', async () => {
    const { token } = await registerAndLogin(app);
    const pp = await createPassport(app, token);
    const targets = ['api.example.com', 'example.com', 'a.b.example.com', 'notexample.com'];
    const ids: Record<string, string> = {};
    for (const t of targets) {
      const r = await deposit(app, token, pp, {
        target: t,
        label: t,
        type: 'api_key',
        secret: `s_${t}`,
      });
      ids[t] = r.id;
    }
    const agent = await issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:*.example.com',
    ]);

    // List is SQL-filtered to exactly the one allowed subdomain.
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(agent.apiKey),
    });
    const items = list.json().items;
    expect(items).toHaveLength(1);
    expect(items[0].target).toBe('api.example.com');

    // Allowed target unseals.
    const okUse = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${ids['api.example.com']}/use`,
      headers: auth(agent.apiKey),
    });
    expect(okUse.statusCode).toBe(200);
    expect(okUse.json().secret).toBe('s_api.example.com');

    // Apex, deeper subdomain, and look-alike are all forbidden.
    for (const t of ['example.com', 'a.b.example.com', 'notexample.com']) {
      const res = await app.inject({
        method: 'POST',
        url: `/v1/vault/credentials/${ids[t]}/use`,
        headers: auth(agent.apiKey),
      });
      expect(res.statusCode, `target ${t} must be forbidden`).toBe(403);
    }
  });

  it('target matching is case-insensitive end-to-end', async () => {
    const { token } = await registerAndLogin(app);
    const pp = await createPassport(app, token);
    // Credential deposited with mixed-case host; agent scoped with lowercase.
    const cred = await deposit(app, token, pp, {
      target: 'GitHub.COM',
      label: 'gh',
      type: 'api_key',
      secret: 'ghp_case',
    });
    const agent = await issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:github.com',
    ]);

    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(agent.apiKey),
    });
    expect(list.json().items).toHaveLength(1);

    const use = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${cred.id}/use`,
      headers: auth(agent.apiKey),
    });
    expect(use.statusCode).toBe(200);
    expect(use.json().secret).toBe('ghp_case');
  });

  it('an expired agent is rejected (401) on vault access', async () => {
    const { token } = await registerAndLogin(app);
    const pp = await createPassport(app, token);
    await deposit(app, token, pp, {
      target: 'github.com',
      label: 'gh',
      type: 'api_key',
      secret: 's',
    });

    const issued = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: {
        passportId: pp,
        name: 'expired',
        scopes: ['vault:read', 'vault:use'],
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      },
    });
    const apiKey = issued.json().apiKey;

    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(apiKey),
    });
    expect(res.statusCode).toBe(401);
  });
});
