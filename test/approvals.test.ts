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

/** Spin up a principal+passport+require-approval credential+agent. */
async function setup(label = 'gh') {
  const { token } = await registerAndLogin(app);
  const pp = await createPassport(app, token);
  const cred = await deposit(app, token, pp, {
    target: 'github.com',
    label,
    type: 'api_key',
    secret: 's3cr3t',
    requireApproval: true,
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

function listApprovals(token: string) {
  return app.inject({ method: 'GET', url: '/v1/approvals', headers: auth(token) });
}

function decide(token: string, id: string, verb: 'approve' | 'deny') {
  return app.inject({
    method: 'POST',
    url: `/v1/approvals/${id}/${verb}`,
    headers: auth(token),
  });
}

describe('approval workflow', () => {
  it('runs the full request -> approve -> use flow with single-use consumption', async () => {
    const { token, credId, apiKey } = await setup();

    // Agent use queues a pending request.
    const first = await use(apiKey, credId);
    expect(first.statusCode).toBe(202);
    const { requestId } = first.json();
    expect(requestId).toBeTruthy();

    // The owner sees it in their queue.
    const queue = await listApprovals(token);
    expect(queue.statusCode).toBe(200);
    const items = queue.json().items;
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe(requestId);
    expect(items[0].credentialId).toBe(credId);

    // Owner approves.
    const approved = await decide(token, requestId, 'approve');
    expect(approved.statusCode).toBe(200);
    expect(approved.json()).toMatchObject({ id: requestId, status: 'approved' });

    // The next use now succeeds and returns the secret (consuming the grant).
    const ok = await use(apiKey, credId);
    expect(ok.statusCode).toBe(200);
    expect(ok.json().secret).toBe('s3cr3t');

    // A second immediate use must re-queue (single-use approval was consumed).
    const second = await use(apiKey, credId);
    expect(second.statusCode).toBe(202);
    expect(second.json().status).toBe('pending');
    expect(second.json().requestId).not.toBe(requestId);

    // The approved request no longer appears as pending; the new one does.
    const queue2 = await listApprovals(token);
    const pendingIds = queue2.json().items.map((i: { id: string }) => i.id);
    expect(pendingIds).toContain(second.json().requestId);
    expect(pendingIds).not.toContain(requestId);
  });

  it('denies a request: agent use returns 403 approval_denied', async () => {
    const { token, credId, apiKey } = await setup('denied-cred');

    const first = await use(apiKey, credId);
    expect(first.statusCode).toBe(202);
    const { requestId } = first.json();

    const denied = await decide(token, requestId, 'deny');
    expect(denied.statusCode).toBe(200);
    expect(denied.json()).toMatchObject({ id: requestId, status: 'denied' });

    const blocked = await use(apiKey, credId);
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('approval_denied');
  });

  it('returns 404 (not 500) for a non-UUID approval id', async () => {
    const { token } = await registerAndLogin(app);
    const a = await decide(token, 'not-a-uuid', 'approve');
    expect(a.statusCode).toBe(404);
    expect(a.json().error.code).toBe('not_found');
    const d = await decide(token, 'not-a-uuid', 'deny');
    expect(d.statusCode).toBe(404);
  });

  it('rejects cross-tenant approve/deny with 404', async () => {
    const { credId, apiKey } = await setup();
    const first = await use(apiKey, credId);
    const { requestId } = first.json();

    // A different principal must not be able to act on the request.
    const { token: otherToken } = await registerAndLogin(app);
    const a = await decide(otherToken, requestId, 'approve');
    expect(a.statusCode).toBe(404);
    const d = await decide(otherToken, requestId, 'deny');
    expect(d.statusCode).toBe(404);

    // And it does not show up in the other principal's queue.
    const queue = await listApprovals(otherToken);
    expect(queue.statusCode).toBe(200);
    expect(queue.json().items).toHaveLength(0);
  });
});
