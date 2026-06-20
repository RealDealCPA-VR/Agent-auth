import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { makeApp, resetDb, registerPrincipal } from './helpers.js';
import { createPassport, depositCredential, useCredential } from '../src/lib/vault.js';

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

describe('useCredential fail-closed agentId guard', () => {
  it('returns not_found for a require-approval credential called without an agentId', async () => {
    // All HTTP routes pass agent.agentId, so this guard is only reachable via a
    // direct lib call. Without an agentId an approval-gated credential cannot
    // materialize an approval row (agent_id is NOT NULL) — fail closed, never 500.
    const p = await registerPrincipal(app);
    const passport = await createPassport(p.id, 'vault');
    const cred = await depositCredential({
      passportId: passport.id,
      target: 'x.example.com',
      label: 'gated',
      type: 'api_key',
      secret: 's3cret',
      requireApproval: true,
    });
    expect(cred).not.toBeNull();

    const res = await useCredential(passport.id, cred!.id, {}); // no agentId
    expect(res.status).toBe('not_found');
  });
});
