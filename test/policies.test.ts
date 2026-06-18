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
import { sql } from '../src/db/index.js';

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

  it('queues a request when approval is required and not yet granted (202 pending)', async () => {
    const { apiKey, credId } = await setup({ requireApproval: true });
    const res = await use(apiKey, credId);
    expect(res.statusCode).toBe(202);
    const body = res.json();
    expect(body.status).toBe('pending');
    expect(body.requestId).toBeTruthy();
  });

  it('allows unlimited use when no policy is set', async () => {
    const { apiKey, credId } = await setup({});
    for (let i = 0; i < 5; i += 1) expect((await use(apiKey, credId)).statusCode).toBe(200);
  });

  it('an out-of-target-scope /use is denied 403 WITHOUT burning a maxUses slot', async () => {
    const { token, pp, credId } = await setup({ maxUses: 1 });
    // Agent authenticated to the passport but scoped for a different target.
    const outOfScope = await issueAgent(app, token, pp, ['vault:use', 'target:other.example']);
    const denied = await use(outOfScope.apiKey, credId);
    expect(denied.statusCode).toBe(403);
    // The single use must still be available to a correctly-scoped agent.
    const inScope = await issueAgent(app, token, pp, ['vault:use', 'target:github.com']);
    expect((await use(inScope.apiKey, credId)).statusCode).toBe(200);
  });

  it('does NOT burn the approval grant when the use is then rejected with use_limit', async () => {
    const { token, apiKey, credId } = await setup({ maxUses: 1, requireApproval: true });
    // Agent requests; human approves (grant now live).
    const pending = await use(apiKey, credId);
    expect(pending.statusCode).toBe(202);
    const { requestId } = pending.json();
    const approved = await app.inject({
      method: 'POST',
      url: `/v1/approvals/${requestId}/approve`,
      headers: auth(token),
    });
    expect(approved.statusCode).toBe(200);
    // Another agent races and consumes the single maxUses slot.
    await sql.unsafe(`UPDATE credentials SET use_count = 1 WHERE id = '${credId}'`);
    // The approved agent retries -> 429 use_limit; its grant must be refunded.
    expect((await use(apiKey, credId)).statusCode).toBe(429);
    // Free the slot; the still-live grant delivers WITHOUT a fresh approval.
    await sql.unsafe(`UPDATE credentials SET use_count = 0 WHERE id = '${credId}'`);
    expect((await use(apiKey, credId)).statusCode).toBe(200);
  });

  it('a decrypt failure returns 500 WITHOUT burning a maxUses slot', async () => {
    const { apiKey, credId } = await setup({ maxUses: 1 });
    // Corrupt the stored auth tag (valid 16-byte length, wrong bytes) so the
    // secret fails to unseal — the reservation must happen only after unseal.
    await sql.unsafe(
      `UPDATE credentials SET sealed = jsonb_set(sealed, '{tag}', '"AAAAAAAAAAAAAAAAAAAAAA=="') WHERE id = '${credId}'`,
    );
    const res = await use(apiKey, credId);
    expect(res.statusCode).toBe(500);
    const [row] = await sql.unsafe<{ use_count: number }[]>(
      `SELECT use_count FROM credentials WHERE id = '${credId}'`,
    );
    expect(Number(row!.use_count)).toBe(0);
  });
});
