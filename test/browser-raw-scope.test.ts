import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { db, schema } from '../src/db/index.js';
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

const SCOPES_TARGET = 'target:app.example.com';

/** POST the browser-login endpoint; raw=true exercises the liability path. */
function call(key: string, id: string, raw: boolean) {
  return app.inject({
    method: 'POST',
    url: `/v1/vault/credentials/${id}/browser-login${raw ? '?raw=true' : ''}`,
    headers: auth(key),
  });
}

async function setupCred(token: string, passportId: string) {
  const cred = await deposit(app, token, passportId, {
    target: 'app.example.com',
    label: 'session',
    type: 'cookie',
    secret: 'sid=abc123',
  });
  return cred.id;
}

describe('raw browser-login plan is gated behind vault:browser:raw', () => {
  it('vault:use only: browserLogin (non-raw) succeeds, getBrowserLoginPlan (raw) is 403 missing_scope', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const agent = await issueAgent(app, token, passportId, ['vault:use', SCOPES_TARGET], 'safe-bot');
    const credId = await setupCred(token, passportId);

    const safe = await call(agent.apiKey, credId, false);
    expect(safe.statusCode).toBe(200);

    const raw = await call(agent.apiKey, credId, true);
    expect(raw.statusCode).toBe(403);
    expect(raw.json().error.code).toBe('missing_scope');
  });

  it('vault:use + vault:browser:raw: both the safe and raw paths succeed', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const agent = await issueAgent(
      app,
      token,
      passportId,
      ['vault:use', 'vault:browser:raw', SCOPES_TARGET],
      'raw-bot',
    );
    const credId = await setupCred(token, passportId);

    expect((await call(agent.apiKey, credId, false)).statusCode).toBe(200);
    expect((await call(agent.apiKey, credId, true)).statusCode).toBe(200);
  });

  it('removing vault:browser:raw mid-session is enforced live: the next raw call is 403', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const agent = await issueAgent(
      app,
      token,
      passportId,
      ['vault:use', 'vault:browser:raw', SCOPES_TARGET],
      'rotating-bot',
    );
    const credId = await setupCred(token, passportId);

    // Raw works while the scope is present.
    expect((await call(agent.apiKey, credId, true)).statusCode).toBe(200);

    // Drop the raw scope (scopes are read fresh from the DB on every request — no
    // per-scope revocation endpoint exists, so simulate the grant being pulled).
    await db
      .update(schema.agents)
      .set({ scopes: ['vault:use', SCOPES_TARGET] })
      .where(eq(schema.agents.id, agent.id));

    // Fail-closed on the very next call.
    const after = await call(agent.apiKey, credId, true);
    expect(after.statusCode).toBe(403);
    expect(after.json().error.code).toBe('missing_scope');
    // The safe path still works (only the raw affordance was withdrawn).
    expect((await call(agent.apiKey, credId, false)).statusCode).toBe(200);
  });

  it('the issuer accepts vault:browser:raw as a valid scope', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(token),
      payload: { passportId, name: 'r', scopes: ['vault:use', 'vault:browser:raw'] },
    });
    expect(res.statusCode).toBe(201);
    expect(res.json().scopes).toContain('vault:browser:raw');
  });
});
