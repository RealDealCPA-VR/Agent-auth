import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  makeApp,
  resetDb,
  auth,
  registerAndLogin,
  createPassport,
  deposit,
  issueAgent,
} from './helpers.js';

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

const GITHUB_SECRET = 'ghp_supersecrettoken_0001';

/** Set up a human + passport + one github.com password credential. */
async function setup() {
  const { token } = await registerAndLogin(app);
  const passportId = await createPassport(app, token, 'vault');
  const cred = await deposit(app, token, passportId, {
    target: 'github.com',
    label: 'gh login',
    type: 'password',
    secret: GITHUB_SECRET,
  });
  return { token, passportId, credId: cred.id };
}

describe('agent-facing vault', () => {
  it('lists the passport credentials for a vault:read agent (pagination envelope)', async () => {
    const { token, passportId, credId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:read', 'target:*']);

    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.pagination).toMatchObject({ total: 1, returned: 1 });
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items).toHaveLength(1);
    expect(body.items[0].id).toBe(credId);
    expect(body.items[0].target).toBe('github.com');
    expect(body.items[0].type).toBe('password');
    // No cleartext secret material is ever exposed by the list endpoint.
    expect(body.items[0].secret).toBeUndefined();
  });

  it('returns 403 listing credentials when the agent lacks vault:read', async () => {
    const { token, passportId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:use', 'target:*']);

    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('forbidden');
  });

  it('unseals the cleartext secret on use for a vault:use agent', async () => {
    const { token, passportId, credId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:use', 'target:*']);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credId}/use`,
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.id).toBe(credId);
    expect(body.target).toBe('github.com');
    expect(body.type).toBe('password');
    expect(body.secret).toBe(GITHUB_SECRET);
  });

  it('returns 403 using a credential when the agent lacks vault:use', async () => {
    const { token, passportId, credId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:read', 'target:*']);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credId}/use`,
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('forbidden');
  });

  it('allows a target:github.com agent to use a github.com credential', async () => {
    const { token, passportId, credId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, [
      'vault:read',
      'vault:use',
      'target:github.com',
    ]);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credId}/use`,
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().secret).toBe(GITHUB_SECRET);
  });

  it('forbids a target:gitlab.com agent from using a github.com credential and hides it from the list', async () => {
    const { token, passportId, credId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, [
      'vault:read',
      'vault:use',
      'target:gitlab.com',
    ]);

    // Filtered out of discovery.
    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(apiKey),
    });
    expect(list.statusCode).toBe(200);
    const listBody = list.json();
    expect(listBody.items).toHaveLength(0);
    expect(listBody.pagination.total).toBe(0);
    expect(listBody.pagination.returned).toBe(0);

    // Forbidden on use.
    const use = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credId}/use`,
      headers: auth(apiKey),
    });
    expect(use.statusCode).toBe(403);
    expect(use.json().error.code).toBe('forbidden');
  });

  it('returns 404 when using a non-existent credential id', async () => {
    const { token, passportId } = await setup();
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:use', 'target:*']);

    const res = await app.inject({
      method: 'POST',
      url: '/v1/vault/credentials/00000000-0000-0000-0000-000000000000/use',
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it('returns 410 when using an expired credential', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token, 'vault');
    const cred = await deposit(app, token, passportId, {
      target: 'github.com',
      label: 'stale gh login',
      type: 'password',
      secret: GITHUB_SECRET,
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:use', 'target:*']);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${cred.id}/use`,
      headers: auth(apiKey),
    });

    expect(res.statusCode).toBe(410);
    expect(res.json().error.code).toBe('expired');
  });

  it('fails closed with 401 on every vault call once the agent is revoked', async () => {
    const { token, passportId, credId } = await setup();
    const agent = await issueAgent(app, token, passportId, ['vault:read', 'vault:use', 'target:*']);

    // Human revokes the agent.
    const revoke = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agent.id}/revoke`,
      headers: auth(token),
    });
    expect(revoke.statusCode).toBe(200);

    const list = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(agent.apiKey),
    });
    expect(list.statusCode).toBe(401);
    expect(list.json().error.code).toBe('unauthorized');

    const use = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credId}/use`,
      headers: auth(agent.apiKey),
    });
    expect(use.statusCode).toBe(401);
    expect(use.json().error.code).toBe('unauthorized');
  });

  it('returns 401 for missing or garbage Bearer tokens', async () => {
    const missing = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
    });
    expect(missing.statusCode).toBe(401);
    expect(missing.json().error.code).toBe('unauthorized');

    const garbage = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth('not-a-real-api-key'),
    });
    expect(garbage.statusCode).toBe(401);
    expect(garbage.json().error.code).toBe('unauthorized');
  });
});
