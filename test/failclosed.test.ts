import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';

// Force the DB liveness probe to report DOWN for this entire file, so we can
// assert the fail-closed behavior without taking the real database offline.
vi.mock('../src/db/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/db/index.js')>();
  return { ...actual, pingDb: vi.fn(async () => false) };
});

import { buildServer } from '../src/server.js';
import { issueSession, verifySession } from '../src/auth/human.js';
import { authenticateAgent } from '../src/auth/agent.js';
import { auth } from './helpers.js';

const FAKE_AGENT_KEY = `aa_11111111-1111-1111-1111-111111111111.${'x'.repeat(40)}`;
const SUB = '22222222-2222-2222-2222-222222222222';

let app: FastifyInstance;
beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});
afterAll(async () => {
  await app.close();
});

describe('fail-closed when the authorization store is unreachable', () => {
  it('agent authentication returns store_unavailable (never default-allow)', async () => {
    const r = await authenticateAgent(FAKE_AGENT_KEY);
    expect(r).toEqual({ ok: false, reason: 'store_unavailable' });
  });

  it('agent-facing vault route returns 503 store_unavailable', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(FAKE_AGENT_KEY),
    });
    expect(res.statusCode).toBe(503);
    expect(res.json().error.code).toBe('store_unavailable');
  });

  it('human session verification is rejected (null) even for a validly-signed token', async () => {
    const session = await issueSession({ sub: SUB, email: 'x@y.test' });
    expect(await verifySession(session.token)).toBeNull();
  });

  it('human-facing route returns 401 for a validly-signed token', async () => {
    const session = await issueSession({ sub: SUB, email: 'x@y.test' });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: auth(session.token),
    });
    expect(res.statusCode).toBe(401);
  });
});
