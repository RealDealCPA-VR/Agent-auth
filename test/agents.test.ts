import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { makeApp, resetDb, auth, registerAndLogin, createPassport, issueAgent } from './helpers.js';

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

describe('agents (human-authenticated issuance / listing / revocation)', () => {
  it('issues an agent (201) returning an aa_ apiKey exactly once, bound to the passport', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);

    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: { passportId, name: 'ci-bot', scopes: ['vault:read', 'vault:use'] },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(typeof body.id).toBe('string');
    expect(typeof body.apiKey).toBe('string');
    expect(body.apiKey.startsWith('aa_')).toBe(true);
    expect(body.scopes).toEqual(['vault:read', 'vault:use']);

    // The plaintext key is shown exactly once: it is NOT returned by list.
    const list = await app.inject({ method: 'GET', url: '/v1/agents', headers: auth(token) });
    expect(list.statusCode).toBe(200);
    const listed = list.json().items.find((a: { id: string }) => a.id === body.id);
    expect(listed).toBeDefined();
    expect(listed.passportId).toBe(passportId);
    expect(listed.apiKey).toBeUndefined();
  });

  it('rejects an over-broad/unknown scope (admin:*) with 400 invalid_scope', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);

    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: { passportId, name: 'evil', scopes: ['vault:read', 'admin:*'] },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_scope');
  });

  it('rejects a non-grantable scope (vault:delete) with 400 invalid_scope', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);

    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: { passportId, name: 'deleter', scopes: ['vault:delete'] },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_scope');
  });

  it("returns 404 when issuing on a passport you don't own", async () => {
    const owner = await registerAndLogin(app);
    const passportId = await createPassport(app, owner.token);

    const stranger = await registerAndLogin(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(stranger.token),
      payload: { passportId, name: 'sneaky', scopes: ['vault:read'] },
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it('accepts valid target globs: exact host, full wildcard, and suffix wildcard', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const scopes = ['vault:read', 'target:github.com', 'target:*', 'target:*.example.com'];

    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: { passportId, name: 'globber', scopes },
    });

    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.apiKey.startsWith('aa_')).toBe(true);
    expect(body.scopes).toEqual(scopes);
  });

  it('lists agents in a pagination envelope, showing active + scopes', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    await issueAgent(app, token, passportId, ['vault:read'], 'a1');
    await issueAgent(app, token, passportId, ['vault:read', 'vault:use'], 'a2');

    const res = await app.inject({ method: 'GET', url: '/v1/agents', headers: auth(token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items).toHaveLength(2);
    expect(body.pagination).toMatchObject({ count: 2 });
    expect(typeof body.pagination.limit).toBe('number');
    expect(typeof body.pagination.offset).toBe('number');

    for (const agent of body.items) {
      expect(agent.active).toBe(true);
      expect(Array.isArray(agent.scopes)).toBe(true);
      expect(agent.passportId).toBe(passportId);
    }
  });

  it("list only returns the caller's own agents", async () => {
    const owner = await registerAndLogin(app);
    const ownerPassport = await createPassport(app, owner.token);
    const mine = await issueAgent(app, owner.token, ownerPassport, ['vault:read'], 'mine');

    const stranger = await registerAndLogin(app);
    const strangerPassport = await createPassport(app, stranger.token);
    await issueAgent(app, stranger.token, strangerPassport, ['vault:read'], 'theirs');

    const res = await app.inject({ method: 'GET', url: '/v1/agents', headers: auth(owner.token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items).toHaveLength(1);
    expect(body.items[0].id).toBe(mine.id);
  });

  it('revokes an agent (200, {revoked:true}) and the list then shows active=false', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const agent = await issueAgent(app, token, passportId, ['vault:read'], 'doomed');

    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agent.id}/revoke`,
      headers: auth(token),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe(agent.id);
    expect(body.revoked).toBe(true);

    const list = await app.inject({ method: 'GET', url: '/v1/agents', headers: auth(token) });
    const listed = list.json().items.find((a: { id: string }) => a.id === agent.id);
    expect(listed).toBeDefined();
    expect(listed.active).toBe(false);
  });

  it("returns 404 when revoking an agent you don't own", async () => {
    const owner = await registerAndLogin(app);
    const passportId = await createPassport(app, owner.token);
    const agent = await issueAgent(app, owner.token, passportId, ['vault:read'], 'protected');

    const stranger = await registerAndLogin(app);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agent.id}/revoke`,
      headers: auth(stranger.token),
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');

    // The agent must remain active for its real owner.
    const list = await app.inject({ method: 'GET', url: '/v1/agents', headers: auth(owner.token) });
    const listed = list.json().items.find((a: { id: string }) => a.id === agent.id);
    expect(listed.active).toBe(true);
  });
});
