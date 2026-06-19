import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { startMockOAuthProvider, type MockOAuthProvider } from './fixtures/mock-oauth-provider.js';

// --- Module isolation: configure env BEFORE importing anything that loads env.ts.
// The mock provider must be running first so its port is in OAUTH_PROVIDERS.
const saved: Record<string, string | undefined> = {};
let mock: MockOAuthProvider;

// Imported lazily after env is set.
let helpers: typeof import('./helpers.js');
let dbmod: typeof import('../src/db/index.js');
let envelope: typeof import('../src/crypto/envelope.js');
let keyprovider: typeof import('../src/crypto/keyprovider/index.js');

let app: FastifyInstance;

beforeAll(async () => {
  mock = await startMockOAuthProvider();
  for (const k of ['OAUTH_PROVIDERS', 'OAUTH_REDIRECT_BASE', 'OAUTH_STATE_TTL_SECONDS'])
    saved[k] = process.env[k];
  process.env.OAUTH_PROVIDERS = JSON.stringify({
    mock: {
      authUrl: mock.authUrl,
      tokenUrl: mock.tokenUrl,
      clientId: 'client-123',
      clientSecret: 'secret-456',
      scopes: ['read', 'write'],
    },
  });
  process.env.OAUTH_REDIRECT_BASE = 'http://localhost:8080';
  process.env.OAUTH_STATE_TTL_SECONDS = '600';

  helpers = await import('./helpers.js');
  dbmod = await import('../src/db/index.js');
  envelope = await import('../src/crypto/envelope.js');
  keyprovider = await import('../src/crypto/keyprovider/index.js');
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

/** Drive a full start -> callback capture, returning ids + tokens for assertions. */
async function captureCredential() {
  const { token, id: principalId } = await helpers.registerAndLogin(app);
  const pp = await helpers.createPassport(app, token);

  const startRes = await app.inject({
    method: 'POST',
    url: `/v1/passports/${pp}/oauth/mock/start`,
    headers: helpers.auth(token),
    payload: { target: 'api.mock.test', label: 'mock creds' },
  });
  const start = startRes.json();

  // Bypass the browser: the callback only needs ?code&state.
  const cbRes = await app.inject({
    method: 'GET',
    url: `/v1/oauth/callback?code=mock-auth-code&state=${encodeURIComponent(start.state)}`,
  });

  return { token, principalId, pp, startRes, start, cbRes };
}

/** Force the stored oauth token set to be expired by re-sealing it. */
async function expireStoredToken(passportId: string, credentialId: string, target: string) {
  const { db, schema } = dbmod;
  const [p] = await db
    .select({ wrappedDek: schema.passports.wrappedDek })
    .from(schema.passports)
    .where(eq(schema.passports.id, passportId))
    .limit(1);
  const dek = await keyprovider.unwrapDek(p!.wrappedDek as never);
  const [cred] = await db
    .select({ sealed: schema.credentials.sealed })
    .from(schema.credentials)
    .where(eq(schema.credentials.id, credentialId))
    .limit(1);
  const aad = Buffer.from(`${passportId}:${target}`);
  const tokens = JSON.parse(
    envelope.open(dek, cred!.sealed as never, aad).toString('utf8'),
  ) as Record<string, unknown>;
  tokens.expires_at = Date.now() - 1000; // already expired
  const reSealed = envelope.seal(dek, Buffer.from(JSON.stringify(tokens), 'utf8'), aad);
  await db
    .update(schema.credentials)
    .set({ sealed: reSealed })
    .where(eq(schema.credentials.id, credentialId));
  dek.fill(0);
}

describe('OAuth credential capture', () => {
  it('start returns authorizeUrl + state and creates a flow', async () => {
    const t = await helpers.registerAndLogin(app);
    const passport = await helpers.createPassport(app, t.token);
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passport}/oauth/mock/start`,
      headers: helpers.auth(t.token),
      payload: {},
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.state).toBeTruthy();
    const url = new URL(body.authorizeUrl);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('client-123');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe(body.state);
    expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:8080/v1/oauth/callback');

    const { db, schema } = dbmod;
    const flows = await db
      .select()
      .from(schema.oauthFlows)
      .where(eq(schema.oauthFlows.state, body.state));
    expect(flows).toHaveLength(1);
    expect(flows[0]!.provider).toBe('mock');
  });

  it('callback exchanges the code and creates an oauth_token credential', async () => {
    const { cbRes, pp } = await captureCredential();
    expect(cbRes.statusCode).toBe(200);
    const body = cbRes.json();
    expect(body.status).toBe('ok');
    expect(body.provider).toBe('mock');
    expect(body.target).toBe('api.mock.test');
    expect(body.credentialId).toBeTruthy();

    const { db, schema } = dbmod;
    const [cred] = await db
      .select()
      .from(schema.credentials)
      .where(eq(schema.credentials.id, body.credentialId))
      .limit(1);
    expect(cred!.type).toBe('oauth_token');
    expect((cred!.metadata as Record<string, unknown>).provider).toBe('mock');

    // The flow row is consumed/deleted.
    const flows = await db.select().from(schema.oauthFlows);
    expect(flows).toHaveLength(0);
    void pp;
  });

  it('an agent using the credential gets the access token', async () => {
    const { token, cbRes } = await captureCredential();
    const credentialId = cbRes.json().credentialId;
    // Re-derive the passport via the principal's only passport.
    const ppList = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: helpers.auth(token),
    });
    const pp = ppList.json().items[0].id;

    const agent = await helpers.issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:api.mock.test',
    ]);
    const useRes = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credentialId}/use`,
      headers: helpers.auth(agent.apiKey),
    });
    expect(useRes.statusCode).toBe(200);
    const body = useRes.json();
    expect(body.type).toBe('oauth_token');
    expect(body.secret).toBe(mock.lastAccessToken());
    expect(body.secret).toMatch(/^access-token-/);
  });

  it('refreshes an expired access token on use and returns the NEW token', async () => {
    const { token, cbRes } = await captureCredential();
    const credentialId = cbRes.json().credentialId;
    const ppList = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: helpers.auth(token),
    });
    const pp = ppList.json().items[0].id;
    const before = mock.lastAccessToken();

    await expireStoredToken(pp, credentialId, 'api.mock.test');

    const agent = await helpers.issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:api.mock.test',
    ]);
    const useRes = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credentialId}/use`,
      headers: helpers.auth(agent.apiKey),
    });
    expect(useRes.statusCode).toBe(200);
    const secret = useRes.json().secret;
    expect(secret).toBe(mock.lastAccessToken());
    expect(secret).not.toBe(before); // a fresh access token was minted
  });

  it('an exhausted maxUses oauth use returns 429 WITHOUT triggering a provider refresh', async () => {
    const { token, cbRes } = await captureCredential();
    const credentialId = cbRes.json().credentialId;
    const ppList = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: helpers.auth(token),
    });
    const pp = ppList.json().items[0].id;
    // Token looks expired (would normally refresh) AND the use cap is exhausted.
    await expireStoredToken(pp, credentialId, 'api.mock.test');
    await dbmod.sql.unsafe(
      `UPDATE credentials SET max_uses = 1, use_count = 1 WHERE id = '${credentialId}'`,
    );
    const before = mock.lastAccessToken();
    const agent = await helpers.issueAgent(app, token, pp, ['vault:use', 'target:api.mock.test']);
    const useRes = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credentialId}/use`,
      headers: helpers.auth(agent.apiKey),
    });
    expect(useRes.statusCode).toBe(429);
    // The maxUses gate fired BEFORE any refresh — the provider was never contacted.
    expect(mock.lastAccessToken()).toBe(before);
  });

  it('rejects an invalid / expired state with 400', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/v1/oauth/callback?code=mock-auth-code&state=does-not-exist',
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_state');
  });

  it('returns 502 when the refresh call fails', async () => {
    const { token, cbRes } = await captureCredential();
    const credentialId = cbRes.json().credentialId;
    const ppList = await app.inject({
      method: 'GET',
      url: '/v1/passports',
      headers: helpers.auth(token),
    });
    const pp = ppList.json().items[0].id;

    await expireStoredToken(pp, credentialId, 'api.mock.test');
    mock.failNextToken();

    const agent = await helpers.issueAgent(app, token, pp, [
      'vault:read',
      'vault:use',
      'target:api.mock.test',
    ]);
    const useRes = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${credentialId}/use`,
      headers: helpers.auth(agent.apiKey),
    });
    expect(useRes.statusCode).toBe(502);
    expect(useRes.json().error.code).toBe('oauth_refresh_failed');
  });
});
