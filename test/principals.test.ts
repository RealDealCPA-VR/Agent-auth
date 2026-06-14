import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  makeApp,
  resetDb,
  auth,
  login,
  registerPrincipal,
  uniqueEmail,
  PASSWORD,
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

describe('principals & sessions', () => {
  it('registers a principal', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/principals',
      payload: { email: uniqueEmail(), password: PASSWORD },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json().id).toBeTruthy();
  });

  it('rejects weak passwords', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/principals',
      payload: { email: uniqueEmail(), password: 'short' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('rejects duplicate email', async () => {
    const p = await registerPrincipal(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/principals',
      payload: { email: p.email, password: PASSWORD },
    });
    expect(res.statusCode).toBe(409);
  });

  it('logs in with valid credentials and returns a token + expiry', async () => {
    const p = await registerPrincipal(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: p.email, password: PASSWORD },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.token).toBeTruthy();
    expect(body.tokenType).toBe('Bearer');
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it('rejects a wrong password and an unknown user identically (401)', async () => {
    const p = await registerPrincipal(app);
    const wrong = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: p.email, password: 'wrong-password-value' },
    });
    const unknown = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { email: uniqueEmail(), password: PASSWORD },
    });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    // Identical except the per-request id — no signal that distinguishes a
    // real account from an unknown one.
    expect(wrong.json().error.code).toBe(unknown.json().error.code);
    expect(wrong.json().error.message).toBe(unknown.json().error.message);
  });

  it('rejects requests without a token', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/passports' });
    expect(res.statusCode).toBe(401);
  });

  it('logout revokes the session token', async () => {
    const p = await registerPrincipal(app);
    const token = await login(app, p.email);
    const out = await app.inject({ method: 'POST', url: '/v1/auth/logout', headers: auth(token) });
    expect(out.statusCode).toBe(200);
    const after = await app.inject({ method: 'GET', url: '/v1/passports', headers: auth(token) });
    expect(after.statusCode).toBe(401);
  });
});
