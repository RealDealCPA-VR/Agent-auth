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

/** Two fully independent tenants A and B, each with a passport + one credential. */
async function twoTenants(): Promise<{
  a: { id: string; token: string; passportId: string; credentialId: string };
  b: { id: string; token: string; passportId: string };
}> {
  const aLogin = await registerAndLogin(app);
  const bLogin = await registerAndLogin(app);

  const aPassport = await createPassport(app, aLogin.token, 'A-vault');
  const bPassport = await createPassport(app, bLogin.token, 'B-vault');

  const aCred = await deposit(app, aLogin.token, aPassport, {
    target: 'github.com',
    label: 'A github',
    type: 'password',
    secret: 'A-super-secret',
  });

  return {
    a: { id: aLogin.id, token: aLogin.token, passportId: aPassport, credentialId: aCred.id },
    b: { id: bLogin.id, token: bLogin.token, passportId: bPassport },
  };
}

describe('cross-tenant isolation / IDOR', () => {
  it("B cannot read A's passport credential listing (404, no existence leak)", async () => {
    const { a, b } = await twoTenants();

    const res = await app.inject({
      method: 'GET',
      url: `/v1/passports/${a.passportId}/credentials`,
      headers: auth(b.token),
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it("B cannot deposit a credential into A's passport (404)", async () => {
    const { a, b } = await twoTenants();

    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${a.passportId}/credentials`,
      headers: auth(b.token),
      payload: {
        target: 'evil.com',
        label: 'B injected',
        type: 'password',
        secret: 'B-injected-secret',
      },
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');

    // And A's listing must be unaffected — still exactly the one original credential.
    const aList = await app.inject({
      method: 'GET',
      url: `/v1/passports/${a.passportId}/credentials`,
      headers: auth(a.token),
    });
    expect(aList.statusCode).toBe(200);
    const items = aList.json().items;
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe(a.credentialId);
  });

  it("B cannot issue an agent bound to A's passport (404)", async () => {
    const { a, b } = await twoTenants();

    const res = await app.inject({
      method: 'POST',
      url: '/v1/agents',
      headers: auth(b.token),
      payload: { passportId: a.passportId, name: 'B-stealer', scopes: ['vault:read', 'vault:use'] },
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
  });

  it("B cannot revoke A's agent (404) and A's agent stays usable", async () => {
    const { a, b } = await twoTenants();
    const agent = await issueAgent(app, a.token, a.passportId, [
      'vault:read',
      'vault:use',
      'target:*',
    ]);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/agents/${agent.id}/revoke`,
      headers: auth(b.token),
    });

    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');

    // The agent must remain active: it can still unseal A's credential.
    const use = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${a.credentialId}/use`,
      headers: auth(agent.apiKey),
    });
    expect(use.statusCode).toBe(200);
    expect(use.json().secret).toBe('A-super-secret');
  });

  it("A's passports never appear in B's passport list", async () => {
    const { a, b } = await twoTenants();

    const res = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: auth(b.token),
    });

    expect(res.statusCode).toBe(200);
    const items = res.json().items;
    const ids = items.map((p: { id: string }) => p.id);
    expect(ids).toContain(b.passportId);
    expect(ids).not.toContain(a.passportId);
    // B sees only its own single passport.
    expect(items).toHaveLength(1);
  });

  it("A's agents never appear in B's agent list", async () => {
    const { a, b } = await twoTenants();
    const aAgent = await issueAgent(app, a.token, a.passportId, ['vault:read', 'vault:use']);

    const res = await app.inject({
      method: 'GET',
      url: '/v1/agents',
      headers: auth(b.token),
    });

    expect(res.statusCode).toBe(200);
    const ids = res.json().items.map((ag: { id: string }) => ag.id);
    expect(ids).not.toContain(aAgent.id);
  });

  it("an agent issued under A cannot list B's credentials (only ever sees its own passport)", async () => {
    const { a, b } = await twoTenants();

    // Give B a credential too, so there is something to (not) leak.
    await deposit(app, b.token, b.passportId, {
      target: 'github.com',
      label: 'B github',
      type: 'password',
      secret: 'B-super-secret',
    });

    const aAgent = await issueAgent(app, a.token, a.passportId, [
      'vault:read',
      'vault:use',
      'target:*',
    ]);

    const res = await app.inject({
      method: 'GET',
      url: '/v1/vault/credentials',
      headers: auth(aAgent.apiKey),
    });

    expect(res.statusCode).toBe(200);
    const items = res.json().items;
    // Only A's single credential is visible to A's agent.
    expect(items).toHaveLength(1);
    expect(items[0].id).toBe(a.credentialId);
    expect(items.every((c: { label: string }) => c.label !== 'B github')).toBe(true);
  });

  it("an agent issued under A cannot unseal B's credential by id (404)", async () => {
    const { a, b } = await twoTenants();

    const bCred = await deposit(app, b.token, b.passportId, {
      target: 'github.com',
      label: 'B github',
      type: 'password',
      secret: 'B-super-secret',
    });

    const aAgent = await issueAgent(app, a.token, a.passportId, [
      'vault:read',
      'vault:use',
      'target:*',
    ]);

    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${bCred.id}/use`,
      headers: auth(aAgent.apiKey),
    });

    // Cross-passport credential id is invisible to A's agent — not_found, never B's secret.
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('not_found');
    expect(JSON.stringify(res.json())).not.toContain('B-super-secret');
  });

  it("B's audit trail never shows A's events", async () => {
    const { a, b } = await twoTenants();

    // Generate distinctive activity on A: issue an agent and use a credential.
    const aAgent = await issueAgent(app, a.token, a.passportId, [
      'vault:read',
      'vault:use',
      'target:*',
    ]);
    await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${a.credentialId}/use`,
      headers: auth(aAgent.apiKey),
    });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/audit',
      headers: auth(b.token),
      query: { limit: '100' },
    });

    expect(res.statusCode).toBe(200);
    const events = res.json().items;

    // Precondition: B must actually have its own events, so the assertions below
    // exercise the scoping filter rather than passing vacuously on an empty array.
    expect(events.length).toBeGreaterThan(0);

    // None of B's audit events may reference A's passport or A's agent.
    expect(events.every((e: { passportId: string | null }) => e.passportId !== a.passportId)).toBe(
      true,
    );
    expect(events.every((e: { agentId: string | null }) => e.agentId !== aAgent.id)).toBe(true);
    expect(
      events.every((e: { credentialId: string | null }) => e.credentialId !== a.credentialId),
    ).toBe(true);
  });

  it("A's own audit trail does contain A's events (positive control)", async () => {
    const { a } = await twoTenants();

    const res = await app.inject({
      method: 'GET',
      url: '/v1/audit',
      headers: auth(a.token),
      query: { limit: '100' },
    });

    expect(res.statusCode).toBe(200);
    const events = res.json().items;
    // A created a passport and deposited a credential — both must be visible to A.
    expect(events.some((e: { passportId: string | null }) => e.passportId === a.passportId)).toBe(
      true,
    );
    expect(
      events.some((e: { credentialId: string | null }) => e.credentialId === a.credentialId),
    ).toBe(true);
  });
});
