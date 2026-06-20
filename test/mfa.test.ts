import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { db, schema } from '../src/db/index.js';
import { MFA_MAX_PENDING, createMfaRequest } from '../src/lib/mfa.js';
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

async function setup(scopes: string[] = ['vault:use', 'target:app.example.com']) {
  const { token, email } = await registerAndLogin(app);
  const passportId = await createPassport(app, token);
  const agent = await issueAgent(app, token, passportId, scopes, 'mfa-bot');
  const cred = await deposit(app, token, passportId, {
    target: 'app.example.com',
    label: 'login',
    type: 'password',
    secret: 'pw',
    metadata: {
      username: 'alice',
      browser: {
        mode: 'form',
        url: 'https://app.example.com/login',
        fields: [
          { selector: '#u', valueFrom: 'username' },
          { selector: '#p', valueFrom: 'secret' },
        ],
        mfa: { kind: 'totp', inputSelector: '#otp' },
      },
    },
  });
  return { token, email, passportId, agentKey: agent.apiKey, agentId: agent.id, credId: cred.id };
}

const reqMfa = (key: string, credId: string, body: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: `/v1/vault/credentials/${credId}/mfa/request`, headers: auth(key), payload: body });
const pollMfa = (key: string, credId: string, reqId: string) =>
  app.inject({ method: 'GET', url: `/v1/vault/credentials/${credId}/mfa/request/${reqId}`, headers: auth(key) });
const listMfa = (token: string) => app.inject({ method: 'GET', url: '/v1/mfa', headers: auth(token) });
const approveMfa = (token: string, id: string, code?: string) =>
  app.inject({ method: 'POST', url: `/v1/mfa/${id}/approve`, headers: auth(token), payload: code !== undefined ? { code } : {} });
const denyMfa = (token: string, id: string) =>
  app.inject({ method: 'POST', url: `/v1/mfa/${id}/deny`, headers: auth(token) });

describe('MFA approval-queue handoff', () => {
  it('full flow: request -> owner approves with code -> agent fetches once -> 410 on second fetch', async () => {
    const s = await setup();
    const r = await reqMfa(s.agentKey, s.credId, {
      challengeId: 'ch1',
      kind: 'totp',
      channelHint: 'authenticator app',
      promptText: 'enter the 6-digit code',
    });
    expect(r.statusCode).toBe(200);
    const requestId = r.json().requestId as string;
    expect(r.json().status).toBe('pending');

    // It surfaces in the owner's queue (non-secret fields only).
    const list = await listMfa(s.token);
    const found = list.json().items.find((m: { id: string }) => m.id === requestId);
    expect(found.kind).toBe('totp');
    expect(found.channelHint).toBe('authenticator app');
    expect(found).not.toHaveProperty('sealedCode');

    expect((await pollMfa(s.agentKey, s.credId, requestId)).json().status).toBe('pending');

    expect((await approveMfa(s.token, requestId, '123456')).statusCode).toBe(200);

    // Agent fetches the code exactly once.
    const got = await pollMfa(s.agentKey, s.credId, requestId);
    expect(got.statusCode).toBe(200);
    expect(got.json().status).toBe('approved');
    expect(got.json().code).toBe('123456');
    expect(got.json().by).toBe(s.email);
    // The secret-bearing response must not be cached by any intermediary.
    expect(got.headers['cache-control']).toContain('no-store');

    // Single-use: second fetch is 410 gone.
    expect((await pollMfa(s.agentKey, s.credId, requestId)).statusCode).toBe(410);

    // Audit trail records the lifecycle but NEVER the code.
    const trail = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(s.token) });
    const acts = (trail.json().items as Array<{ action: string }>).map((i) => i.action);
    expect(acts).toEqual(expect.arrayContaining(['mfa.requested', 'mfa.approved', 'mfa.consumed']));
    expect(JSON.stringify(trail.json())).not.toContain('123456');
  });

  it('push/webauthn: approve with no code yields an approved result with code=null', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'p', kind: 'push' })).json().requestId;
    expect((await approveMfa(s.token, requestId)).statusCode).toBe(200);
    const got = await pollMfa(s.agentKey, s.credId, requestId);
    expect(got.json().status).toBe('approved');
    expect(got.json().code).toBeNull();
  });

  it('expired request returns 410 and audits mfa.expired ONCE no matter how often polled', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'e', kind: 'sms' })).json().requestId;
    await db
      .update(schema.mfaRequests)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(schema.mfaRequests.id, requestId));

    // Poll several times — each is 410 expired, but only the transition is audited.
    for (let i = 0; i < 4; i += 1) {
      const res = await pollMfa(s.agentKey, s.credId, requestId);
      expect(res.statusCode).toBe(410);
      expect(res.json().error.code).toBe('expired');
    }

    const trail = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(s.token) });
    const expiredEvents = (trail.json().items as Array<{ action: string }>).filter(
      (i) => i.action === 'mfa.expired',
    );
    expect(expiredEvents).toHaveLength(1);
  });

  it('denied request: the agent poll returns status denied', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'd', kind: 'email' })).json().requestId;
    expect((await denyMfa(s.token, requestId)).statusCode).toBe(200);
    expect((await pollMfa(s.agentKey, s.credId, requestId)).json().status).toBe('denied');
  });

  it('denying an already-EXPIRED (unflipped) request is rejected (409) so it resolves as expired, not denied', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'de', kind: 'sms' })).json().requestId;
    // Force the TTL into the past WITHOUT flipping status (no poll yet): row is still 'pending'.
    await db
      .update(schema.mfaRequests)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(schema.mfaRequests.id, requestId));

    // Deny must refuse (mirrors approve's TTL guard) rather than recording mfa.denied.
    expect((await denyMfa(s.token, requestId)).statusCode).toBe(409);
    // The agent poll then resolves it as expired, the truthful terminal state.
    const poll = await pollMfa(s.agentKey, s.credId, requestId);
    expect(poll.statusCode).toBe(410);
    expect(poll.json().error.code).toBe('expired');

    const trail = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(s.token) });
    const actions = (trail.json().items as Array<{ action: string }>).map((i) => i.action);
    expect(actions).not.toContain('mfa.denied');
    expect(actions).toContain('mfa.expired');
  });

  it('revoking the agent cancels its pending MFA (status revoked) and audits mfa.revoked', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'r', kind: 'totp' })).json().requestId;
    await app.inject({ method: 'POST', url: `/v1/agents/${s.agentId}/revoke`, headers: auth(s.token) });

    const [row] = await db
      .select({ status: schema.mfaRequests.status })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    expect(row!.status).toBe('revoked');

    const trail = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(s.token) });
    expect((trail.json().items as Array<{ action: string }>).map((i) => i.action)).toContain('mfa.revoked');
    // No longer in the owner's pending queue.
    const list = await listMfa(s.token);
    expect(list.json().items.find((m: { id: string }) => m.id === requestId)).toBeUndefined();
  });

  it('revoking the agent also cancels an APPROVED-but-unfetched request and zeroes its sealed code', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'a', kind: 'totp' })).json().requestId;
    expect((await approveMfa(s.token, requestId, '123456')).statusCode).toBe(200); // approved, sealedCode set

    await app.inject({ method: 'POST', url: `/v1/agents/${s.agentId}/revoke`, headers: auth(s.token) });

    const [row] = await db
      .select({ status: schema.mfaRequests.status, sealed: schema.mfaRequests.sealedCode })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    expect(row!.status).toBe('revoked');
    expect(row!.sealed).toBeNull(); // the sealed-but-unfetched code is zeroed
  });

  it('consuming a code zeroes the sealed code at rest (uniform destroy-on-terminal invariant)', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'cz', kind: 'totp' })).json().requestId;
    expect((await approveMfa(s.token, requestId, '123456')).statusCode).toBe(200);
    // The single-use fetch delivers the code...
    expect((await pollMfa(s.agentKey, s.credId, requestId)).json().code).toBe('123456');

    const [row] = await db
      .select({ status: schema.mfaRequests.status, sealed: schema.mfaRequests.sealedCode })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    expect(row!.status).toBe('consumed');
    expect(row!.sealed).toBeNull(); // ...and the spent one-time code no longer lingers sealed
  });

  it('lazy-expiring an APPROVED-but-unfetched request also zeroes its sealed code at rest', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'ae', kind: 'totp' })).json().requestId;
    expect((await approveMfa(s.token, requestId, '123456')).statusCode).toBe(200); // approved, sealedCode set
    // Drive the TTL past without fetching; the next agent poll lazily flips to expired.
    await db
      .update(schema.mfaRequests)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(schema.mfaRequests.id, requestId));

    const poll = await pollMfa(s.agentKey, s.credId, requestId);
    expect(poll.statusCode).toBe(410);
    expect(poll.json().error.code).toBe('expired');

    const [row] = await db
      .select({ status: schema.mfaRequests.status, sealed: schema.mfaRequests.sealedCode })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    expect(row!.status).toBe('expired');
    expect(row!.sealed).toBeNull(); // a one-time code that can no longer be delivered is destroyed
  });

  it('createMfaRequest refuses a credential that does not belong to the passport (self-scope DiD)', async () => {
    const s = await setup();
    // A second principal + passport; the credential s.credId belongs to s.passportId.
    const other = await registerAndLogin(app);
    const otherPassportId = await createPassport(app, other.token);
    // Forge a (foreign-passport, this-credential) pairing. The vault route blocks this
    // via getCredentialMeta scoping, but createMfaRequest must self-scope and reject too.
    const res = await createMfaRequest({
      passportId: otherPassportId,
      credentialId: s.credId,
      agentId: s.agentId,
      challengeId: 'forge',
      kind: 'totp',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('not_found');
  });

  it('createMfaRequest refuses an agent that does not belong to the passport (self-scope DiD)', async () => {
    const s = await setup();
    // A second principal + passport + agent; that agent is foreign to s.passportId.
    const other = await registerAndLogin(app);
    const otherPassportId = await createPassport(app, other.token);
    const otherAgent = await issueAgent(app, other.token, otherPassportId, ['vault:use', 'target:app.example.com'], 'x');
    // Pair this passport's credential with a FOREIGN agent — must self-scope and reject.
    const res = await createMfaRequest({
      passportId: s.passportId,
      credentialId: s.credId,
      agentId: otherAgent.id,
      challengeId: 'forge-agent',
      kind: 'totp',
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe('not_found');
  });

  it('a stranger cannot approve another owner\'s MFA request (404)', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'x', kind: 'totp' })).json().requestId;
    const stranger = await registerAndLogin(app);
    expect((await approveMfa(stranger.token, requestId, '999999')).statusCode).toBe(404);
  });

  it('a configured delegateApproverId can approve the credential\'s MFA request', async () => {
    const { token: ownerToken } = await registerAndLogin(app);
    const passportId = await createPassport(app, ownerToken);
    const delegate = await registerAndLogin(app);
    const agent = await issueAgent(app, ownerToken, passportId, ['vault:use', 'target:app.example.com'], 'mfa-bot');
    const cred = await deposit(app, ownerToken, passportId, {
      target: 'app.example.com',
      label: 'login',
      type: 'password',
      secret: 'pw',
      metadata: { delegateApproverId: delegate.id, browser: { mode: 'cookie' } },
    });
    const requestId = (await reqMfa(agent.apiKey, cred.id, { challengeId: 'g', kind: 'totp' })).json().requestId;

    // The delegate (not the owner) approves.
    expect((await approveMfa(delegate.token, requestId, '424242')).statusCode).toBe(200);
    const got = await pollMfa(agent.apiKey, cred.id, requestId);
    expect(got.json().code).toBe('424242');
  });

  it('a delegate removed from the credential metadata can no longer approve (authz re-checked)', async () => {
    const { token: ownerToken } = await registerAndLogin(app);
    const passportId = await createPassport(app, ownerToken);
    const delegate = await registerAndLogin(app);
    const agent = await issueAgent(app, ownerToken, passportId, ['vault:use', 'target:app.example.com'], 'mfa-bot');
    const cred = await deposit(app, ownerToken, passportId, {
      target: 'app.example.com',
      label: 'login',
      type: 'password',
      secret: 'pw',
      metadata: { delegateApproverId: delegate.id, browser: { mode: 'cookie' } },
    });
    const requestId = (await reqMfa(agent.apiKey, cred.id, { challengeId: 'gx', kind: 'totp' })).json().requestId;

    // Owner revokes the delegation by clearing it from the credential metadata.
    await db
      .update(schema.credentials)
      .set({ metadata: { browser: { mode: 'cookie' } } })
      .where(eq(schema.credentials.id, cred.id));

    // The ex-delegate's approval is now refused (existence hidden as 404), and the
    // agent never receives a code — the authorization is re-evaluated, not cached.
    expect((await approveMfa(delegate.token, requestId, '424242')).statusCode).toBe(404);
    expect((await pollMfa(agent.apiKey, cred.id, requestId)).json().status).toBe('pending');
  });

  it('rate-limits pending MFA requests per credential+agent', async () => {
    const s = await setup();
    for (let i = 0; i < MFA_MAX_PENDING; i += 1) {
      expect((await reqMfa(s.agentKey, s.credId, { challengeId: `c${i}`, kind: 'totp' })).statusCode).toBe(200);
    }
    const over = await reqMfa(s.agentKey, s.credId, { challengeId: 'over', kind: 'totp' });
    expect(over.statusCode).toBe(429);
    expect(over.json().error.code).toBe('rate_limited');
  });

  it('the pending limit holds under CONCURRENT requests (no check-then-insert race)', async () => {
    const s = await setup();
    const N = MFA_MAX_PENDING + 4;
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) => reqMfa(s.agentKey, s.credId, { challengeId: `c${i}`, kind: 'totp' })),
    );
    const ok = results.filter((r) => r.statusCode === 200).length;
    const limited = results.filter((r) => r.statusCode === 429).length;
    expect(ok).toBe(MFA_MAX_PENDING); // exactly the cap, not cap+concurrency
    expect(limited).toBe(N - MFA_MAX_PENDING);
  });

  it('approving a code-kind (totp) request without a code is rejected (400)', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'c', kind: 'totp' })).json().requestId;
    const res = await approveMfa(s.token, requestId); // no code typed
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('does NOT burn an approved MFA row when the sealed code cannot be unsealed', async () => {
    const s = await setup();
    const requestId = (await reqMfa(s.agentKey, s.credId, { challengeId: 'c', kind: 'totp' })).json().requestId;
    expect((await approveMfa(s.token, requestId, '123456')).statusCode).toBe(200);

    // Corrupt the sealed code's tag so unseal fails (tamper / wrong-key simulation).
    const [row] = await db
      .select({ sealed: schema.mfaRequests.sealedCode })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    const corrupted = { ...(row!.sealed as Record<string, unknown>), tag: 'AAAAAAAAAAAAAAAAAAAAAA==' };
    await db.update(schema.mfaRequests).set({ sealedCode: corrupted }).where(eq(schema.mfaRequests.id, requestId));

    // The code can't be unsealed → the row is NOT consumed (no burn): poll reports
    // pending and the row stays 'approved' so a recovery/retry remains possible.
    const poll = await pollMfa(s.agentKey, s.credId, requestId);
    expect(poll.statusCode).toBe(200);
    expect(poll.json().status).toBe('pending');
    const [after] = await db
      .select({ status: schema.mfaRequests.status })
      .from(schema.mfaRequests)
      .where(eq(schema.mfaRequests.id, requestId))
      .limit(1);
    expect(after!.status).toBe('approved');
  });

  it('requires vault:use to open an MFA request', async () => {
    const s = await setup(['vault:read', 'target:app.example.com']);
    const res = await reqMfa(s.agentKey, s.credId, { challengeId: 'c', kind: 'totp' });
    expect(res.statusCode).toBe(403);
  });
});
