import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';

// Build the server with a tiny global limit (env must be set before src/env loads,
// so import buildServer dynamically) and confirm a throttled request returns a
// clean 429 + rate_limited envelope — NOT a 500 from the generic error handler.
const saved: Record<string, string | undefined> = {};
let app: FastifyInstance;

beforeAll(async () => {
  for (const k of ['RATE_LIMIT_GLOBAL_MAX', 'RATE_LIMIT_AUTH_MAX']) saved[k] = process.env[k];
  process.env.RATE_LIMIT_GLOBAL_MAX = '2';
  process.env.RATE_LIMIT_AUTH_MAX = '2';
  const { buildServer } = await import('../src/server.js');
  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app?.close();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

describe('rate limiting', () => {
  it('returns 429 + rate_limited envelope (not 500) when the limit is exceeded', async () => {
    let last;
    for (let i = 0; i < 5; i += 1) {
      last = await app.inject({ method: 'GET', url: '/healthz' });
    }
    expect(last!.statusCode).toBe(429);
    expect(last!.json().error.code).toBe('rate_limited');
    expect(last!.headers['retry-after']).toBeDefined();
  });
});
