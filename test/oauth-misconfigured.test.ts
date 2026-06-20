import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { startMockOAuthProvider, type MockOAuthProvider } from './fixtures/mock-oauth-provider.js';

// OAuth start with a configured provider but OAUTH_REDIRECT_BASE UNSET must fail
// fast with 500 oauth_misconfigured (the server can't build a redirect_uri). env
// is read once at module load, so we configure OAUTH_PROVIDERS (a real provider
// must exist so we get past the unknown_provider gate) while leaving
// OAUTH_REDIRECT_BASE unset, BEFORE importing anything that loads src/env.ts.

const saved: Record<string, string | undefined> = {};
let mock: MockOAuthProvider;
let helpers: typeof import('./helpers.js');
let app: FastifyInstance;

beforeAll(async () => {
  mock = await startMockOAuthProvider();
  for (const k of ['OAUTH_PROVIDERS', 'OAUTH_REDIRECT_BASE']) saved[k] = process.env[k];
  process.env.OAUTH_PROVIDERS = JSON.stringify({
    mock: {
      authUrl: mock.authUrl,
      tokenUrl: mock.tokenUrl,
      clientId: 'client-123',
      clientSecret: 'secret-456',
      scopes: ['read', 'write'],
    },
  });
  delete process.env.OAUTH_REDIRECT_BASE; // the misconfiguration under test

  helpers = await import('./helpers.js');
  app = await helpers.makeApp();
});

afterAll(async () => {
  await app?.close();
  await mock.close();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

beforeEach(async () => {
  await helpers.resetDb();
});

describe('OAuth start without OAUTH_REDIRECT_BASE', () => {
  it('returns 500 oauth_misconfigured', async () => {
    const { token } = await helpers.registerAndLogin(app);
    const pp = await helpers.createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${pp}/oauth/mock/start`,
      headers: helpers.auth(token),
      payload: {},
    });
    expect(res.statusCode).toBe(500);
    expect(res.json().error.code).toBe('oauth_misconfigured');
  });
});
