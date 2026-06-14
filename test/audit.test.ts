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

const SECRET = 'super-secret-vault-value-9f3c-do-not-leak';

/**
 * Drive a full lifecycle (register+login already happened) and return the
 * caller's token plus the ids involved, so each test can inspect the trail.
 */
async function runLifecycle(): Promise<{
  token: string;
  passportId: string;
  credentialId: string;
  agentId: string;
}> {
  const { token } = await registerAndLogin(app);
  const passportId = await createPassport(app, token, 'prod-vault');
  const { id: credentialId } = await deposit(app, token, passportId, {
    target: 'github.com',
    label: 'gh-login',
    type: 'password',
    secret: SECRET,
  });
  const { id: agentId, apiKey } = await issueAgent(app, token, passportId);

  // Agent uses the credential (records a credential.use event).
  const useRes = await app.inject({
    method: 'POST',
    url: `/v1/vault/credentials/${credentialId}/use`,
    headers: auth(apiKey),
  });
  expect(useRes.statusCode).toBe(200);
  expect(useRes.json().secret).toBe(SECRET);

  // Revoke the agent (records an agent.revoke event).
  const revRes = await app.inject({
    method: 'POST',
    url: `/v1/agents/${agentId}/revoke`,
    headers: auth(token),
  });
  expect(revRes.statusCode).toBe(200);

  return { token, passportId, credentialId, agentId };
}

beforeAll(async () => {
  app = await makeApp();
});
afterAll(async () => {
  await app.close();
});
beforeEach(async () => {
  await resetDb();
});

describe('audit trail + tamper evidence', () => {
  it('requires authentication on /v1/audit', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/audit' });
    expect(res.statusCode).toBe(401);
  });

  it('requires authentication on /v1/audit/verify', async () => {
    const res = await app.inject({ method: 'GET', url: '/v1/audit/verify' });
    expect(res.statusCode).toBe(401);
  });

  it('returns a paginated audit trail covering the full lifecycle', async () => {
    const { token } = await runLifecycle();

    const res = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();

    // Pagination envelope.
    expect(body.pagination).toMatchObject({
      limit: expect.any(Number),
      offset: expect.any(Number),
    });
    expect(body.pagination.count).toBe(body.items.length);
    expect(Array.isArray(body.items)).toBe(true);

    const actions = body.items.map((e: { action: string }) => e.action);
    expect(actions).toContain('passport.create');
    expect(actions).toContain('credential.deposit');
    expect(actions).toContain('agent.issue');
    expect(actions).toContain('credential.use');
    expect(actions).toContain('agent.revoke');
  });

  it('scopes the audit trail to the calling principal', async () => {
    // First principal performs the lifecycle.
    await runLifecycle();

    // A second, fresh principal must not see the first principal's events.
    const { token: otherToken } = await registerAndLogin(app);
    const res = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(otherToken) });
    expect(res.statusCode).toBe(200);
    const body = res.json();

    const actions = body.items.map((e: { action: string }) => e.action);
    // The other principal only sees its own principal-level events (its login),
    // never another caller's passport/credential/agent events.
    expect(actions).not.toContain('passport.create');
    expect(actions).not.toContain('credential.deposit');
    expect(actions).not.toContain('credential.use');
    expect(actions).not.toContain('agent.issue');
    expect(actions).not.toContain('agent.revoke');
  });

  it('never leaks the deposited secret into any audit event detail', async () => {
    const { token } = await runLifecycle();

    const res = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();

    expect(body.items.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(body.items);
    expect(serialized).not.toContain(SECRET);
    for (const ev of body.items) {
      expect(JSON.stringify(ev.detail ?? {})).not.toContain(SECRET);
    }
  });

  it('verifies an intact hash chain as ok', async () => {
    const { token } = await runLifecycle();

    const res = await app.inject({ method: 'GET', url: '/v1/audit/verify', headers: auth(token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(true);
    expect(body.brokenAtSeq).toBeNull();
  });

  it('detects tampering by reporting the broken sequence number', async () => {
    const { token } = await runLifecycle();

    // Pick a real row to tamper (flip its success flag).
    const [target] = await sql.unsafe<{ seq: number }[]>(
      "SELECT seq FROM audit_events WHERE action = 'credential.deposit' ORDER BY seq ASC LIMIT 1",
    );
    expect(target).toBeDefined();
    const brokenSeq = Number(target.seq);

    // The append-only trigger blocks updates; disable it to forge a tamper.
    await sql.unsafe('ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_mutate');
    try {
      await sql.unsafe(`UPDATE audit_events SET success = false WHERE seq = ${brokenSeq}`);
    } finally {
      await sql.unsafe('ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_mutate');
    }

    const res = await app.inject({ method: 'GET', url: '/v1/audit/verify', headers: auth(token) });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.ok).toBe(false);
    expect(body.brokenAtSeq).toBe(brokenSeq);
  });

  it('blocks a normal DELETE via the append-only trigger', async () => {
    await runLifecycle();

    let threw = false;
    try {
      await sql.unsafe("DELETE FROM audit_events WHERE action = 'credential.deposit'");
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);

    // The row must still be present after the rejected delete.
    const [{ count }] = await sql.unsafe<{ count: string }[]>(
      "SELECT count(*)::int AS count FROM audit_events WHERE action = 'credential.deposit'",
    );
    expect(Number(count)).toBeGreaterThan(0);
  });

  it('records a failed credential.use attempt (success=false) without the secret', async () => {
    const { token } = await registerAndLogin(app);
    const passportId = await createPassport(app, token, 'scoped-vault');
    const { id: credentialId } = await deposit(app, token, passportId, {
      target: 'github.com',
      label: 'gh-login',
      type: 'password',
      secret: SECRET,
    });
    // Issue an agent with read-only scope: vault:use is missing -> use is denied.
    const { apiKey } = await issueAgent(app, token, passportId, ['vault:read']);

    const useRes = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credentialId}/use`,
      headers: auth(apiKey),
    });
    expect(useRes.statusCode).toBe(403);
    expect(useRes.json().error.code).toBe('forbidden');

    const res = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(token) });
    const body = res.json();
    const denied = body.items.find(
      (e: { action: string; success: boolean }) =>
        e.action === 'credential.use' && e.success === false,
    );
    expect(denied).toBeDefined();
    expect(JSON.stringify(body.items)).not.toContain(SECRET);

    // The chain stays intact after recording a failed event.
    const verify = await app.inject({
      method: 'GET',
      url: '/v1/audit/verify',
      headers: auth(token),
    });
    expect(verify.json().ok).toBe(true);
  });
});
