import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { makeApp, resetDb, auth, registerAndLogin, createPassport, deposit } from './helpers.js';

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

describe('passports & credential deposit', () => {
  it('creates a passport (201) returning id, name and createdAt', async () => {
    const { token } = await registerAndLogin(app);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/passports',
      headers: auth(token),
      payload: { name: 'github-bot' },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.id).toBeTruthy();
    expect(body.name).toBe('github-bot');
    expect(new Date(body.createdAt).getTime()).toBeGreaterThan(0);
    // The deposit secret is never part of a passport row, but ensure no leak here either.
    expect(body).not.toHaveProperty('secret');
  });

  it('requires auth to create a passport (401 without token)', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/passports',
      payload: { name: 'no-auth' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('lists passports in a pagination envelope, scoped to the caller', async () => {
    const a = await registerAndLogin(app);
    const b = await registerAndLogin(app);
    await createPassport(app, a.token, 'a-one');
    await createPassport(app, a.token, 'a-two');
    await createPassport(app, b.token, 'b-only');

    const res = await app.inject({ method: 'GET', url: '/v1/passports', headers: auth(a.token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items).toHaveLength(2);
    expect(body.pagination).toEqual({ limit: 50, offset: 0, count: 2 });
    const names = body.items.map((p: { name: string }) => p.name).sort();
    expect(names).toEqual(['a-one', 'a-two']);
    // Caller a must not see caller b's passport.
    expect(names).not.toContain('b-only');
  });

  it('respects limit and offset when listing passports', async () => {
    const { token } = await registerAndLogin(app);
    for (let i = 0; i < 3; i += 1) await createPassport(app, token, `vault-${i}`);

    const first = await app.inject({
      method: 'GET',
      url: '/v1/passports?limit=2&offset=0',
      headers: auth(token),
    });
    expect(first.statusCode).toBe(200);
    expect(first.json().items).toHaveLength(2);
    expect(first.json().pagination).toEqual({ limit: 2, offset: 0, count: 2 });

    const second = await app.inject({
      method: 'GET',
      url: '/v1/passports?limit=2&offset=2',
      headers: auth(token),
    });
    expect(second.statusCode).toBe(200);
    expect(second.json().items).toHaveLength(1);
    expect(second.json().pagination).toEqual({ limit: 2, offset: 2, count: 1 });
  });

  it('deposits a credential (201) without echoing the secret', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: {
        target: 'github.com',
        label: 'ci-login',
        type: 'password',
        secret: 'super-secret-value',
        metadata: { note: 'service account' },
      },
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.id).toBeTruthy();
    expect(body.target).toBe('github.com');
    expect(body.type).toBe('password');
    expect(body).not.toHaveProperty('secret');
  });

  it('returns 404 when depositing into a passport you do not own', async () => {
    const owner = await registerAndLogin(app);
    const attacker = await registerAndLogin(app);
    const passportId = await createPassport(app, owner.token);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(attacker.token),
      payload: { target: 'github.com', label: 'x', type: 'password', secret: 's3cret' },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it('rejects oversized metadata (JSON > 4 KiB) with 400', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const big = 'x'.repeat(4200);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: {
        target: 'github.com',
        label: 'big',
        type: 'password',
        secret: 'value',
        metadata: { blob: big },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('rejects an invalid credential type with 400', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: { target: 'github.com', label: 'l', type: 'totally_invalid', secret: 'value' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('rejects a deposit missing required fields with 400', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: { target: 'github.com' }, // missing label, type, secret
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('lists credential metadata (no secret) in a pagination envelope', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    await deposit(app, token, passportId, {
      target: 'github.com',
      label: 'ci-login',
      type: 'password',
      secret: 'super-secret-value',
      metadata: { env: 'prod' },
    });

    const res = await app.inject({
      method: 'GET',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.items).toHaveLength(1);
    expect(body.pagination).toEqual({ limit: 50, offset: 0, count: 1 });
    const cred = body.items[0];
    expect(cred.target).toBe('github.com');
    expect(cred.type).toBe('password');
    expect(cred.metadata).toEqual({ env: 'prod' });
    expect(cred).not.toHaveProperty('secret');
  });

  it('returns 404 when listing credentials of a passport you do not own', async () => {
    const owner = await registerAndLogin(app);
    const attacker = await registerAndLogin(app);
    const passportId = await createPassport(app, owner.token);
    await deposit(app, owner.token, passportId, {
      target: 'github.com',
      label: 'l',
      type: 'password',
      secret: 'value',
    });

    const res = await app.inject({
      method: 'GET',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(attacker.token),
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });
});
