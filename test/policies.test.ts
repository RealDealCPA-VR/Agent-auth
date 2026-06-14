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

async function setup(policy: Record<string, unknown>) {
  const { token } = await registerAndLogin(app);
  const pp = await createPassport(app, token);
  const cred = await deposit(app, token, pp, {
    target: 'github.com',
    label: 'gh',
    type: 'api_key',
    secret: 's3cr3t',
    ...policy,
  });
  const agent = await issueAgent(app, token, pp, ['vault:read', 'vault:use', 'target:github.com']);
  return { token, pp, credId: cred.id, apiKey: agent.apiKey };
}

function use(apiKey: string, id: string) {
  return app.inject({
    method: 'POST',
    url: `/v1/vault/credentials/${id}/use`,
    headers: auth(apiKey),
  });
}

describe('per-credential policies', () => {
  it('enforces maxUses (atomic; the N+1th use is 429)', async () => {
    const { apiKey, credId } = await setup({ maxUses: 2 });
    expect((await use(apiKey, credId)).statusCode).toBe(200);
    expect((await use(apiKey, credId)).statusCode).toBe(200);
    const third = await use(apiKey, credId);
    expect(third.statusCode).toBe(429);
    expect(third.json().error.code).toBe('use_limit_reached');
  });

  it('rejects use before the allowed window (403 not_yet_valid)', async () => {
    const { apiKey, credId } = await setup({
      allowedFrom: new Date(Date.now() + 3600_000).toISOString(),
    });
    const res = await use(apiKey, credId);
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('not_yet_valid');
  });

  it('rejects use after the allowed window (410 window_expired)', async () => {
    const { apiKey, credId } = await setup({
      allowedUntil: new Date(Date.now() - 1000).toISOString(),
    });
    const res = await use(apiKey, credId);
    expect(res.statusCode).toBe(410);
    expect(res.json().error.code).toBe('window_expired');
  });

  it('blocks use when approval is required and not granted (403 approval_required)', async () => {
    const { apiKey, credId } = await setup({ requireApproval: true });
    const res = await use(apiKey, credId);
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('approval_required');
  });

  it('allows unlimited use when no policy is set', async () => {
    const { apiKey, credId } = await setup({});
    for (let i = 0; i < 5; i += 1) expect((await use(apiKey, credId)).statusCode).toBe(200);
  });
});
