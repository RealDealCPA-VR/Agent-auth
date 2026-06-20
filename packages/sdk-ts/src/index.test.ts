import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AgentAuthClient,
  AgentAuthError,
  ApprovalPendingError,
  HumanClient,
  applyBrowserLogin,
  type BrowserLoginPlan,
  type BrowserPage,
  type MfaChallenge,
  type Page,
  type PlanCookie,
  type UsedCredential,
  type VaultCredential,
} from './index.js';

const BASE = 'https://vault.example.test';
const API_KEY = 'aa_11111111-1111-1111-1111-111111111111.s3cr3t';
const TOKEN = 'jwt.header.payload';

// --- fetch mock helpers -----------------------------------------------------

interface MockResponseSpec {
  status?: number;
  body?: unknown;
  /** Override the serialized text body (e.g. to simulate malformed JSON). */
  text?: string;
}

/** Build a minimal `Response`-like object good enough for the SDK transport. */
function makeResponse(spec: MockResponseSpec): Response {
  const status = spec.status ?? 200;
  const text =
    spec.text !== undefined ? spec.text : spec.body !== undefined ? JSON.stringify(spec.body) : '';
  return {
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(text),
  } as unknown as Response;
}

/** A captured fetch call (url + parsed init), for assertions. */
interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

/**
 * Stub global fetch with a queue of responses. Returns the captured calls array
 * and a helper. Each fetch call shifts the next response off `responses`; if the
 * queue is exhausted the last response repeats.
 */
function stubFetch(responses: MockResponseSpec[]): { calls: Call[] } {
  const calls: Call[] = [];
  let idx = 0;
  const impl = vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    });
    const spec = responses[Math.min(idx, responses.length - 1)] ?? {};
    idx += 1;
    return Promise.resolve(makeResponse(spec));
  });
  vi.stubGlobal('fetch', impl);
  return { calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// --- AgentAuthClient: success paths -----------------------------------------

describe('AgentAuthClient.listCredentials', () => {
  it('GETs the vault listing with the agent bearer key and pagination', async () => {
    const pageBody: Page<VaultCredential> = {
      items: [
        {
          id: 'c1',
          target: 'github.com',
          label: 'GH',
          type: 'api_key',
          metadata: {},
          expiresAt: null,
        },
      ],
      pagination: { limit: 25, offset: 0, total: 1, returned: 1 },
    };
    const { calls } = stubFetch([{ body: pageBody }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.listCredentials({ limit: 25 });

    expect(result.items[0]?.target).toBe('github.com');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('GET');
    expect(calls[0]?.url).toBe(`${BASE}/v1/vault/credentials?limit=25`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${API_KEY}`);
  });

  it('normalizes a trailing slash in baseUrl', async () => {
    const { calls } = stubFetch([
      { body: { items: [], pagination: { limit: 50, offset: 0, total: 0, returned: 0 } } },
    ]);
    const aa = new AgentAuthClient({ baseUrl: `${BASE}/`, apiKey: API_KEY });
    await aa.listCredentials();
    expect(calls[0]?.url.startsWith(`${BASE}/v1/vault/credentials`)).toBe(true);
    expect(calls[0]?.url).not.toContain('//v1');
  });
});

describe('AgentAuthClient.useCredential by id (UUID)', () => {
  it('POSTs straight to /use without a listing round-trip', async () => {
    const id = '22222222-2222-4222-8222-222222222222';
    const used: UsedCredential = {
      id,
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'ghp_supersecret',
    };
    const { calls } = stubFetch([{ body: used }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.useCredential(id);

    expect(result.secret).toBe('ghp_supersecret');
    // Only one call — no listing needed because the input is a UUID.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe(`${BASE}/v1/vault/credentials/${id}/use`);
  });
});

// --- AgentAuthClient: proxy mode --------------------------------------------

describe('AgentAuthClient.proxy by id (UUID)', () => {
  it('POSTs the proxy path with the request body and bearer key', async () => {
    const id = '66666666-6666-4666-8666-666666666666';
    const proxyResp = {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: '{"login":"octocat"}',
    };
    const { calls } = stubFetch([{ body: proxyResp }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.proxy(id, { method: 'GET', path: '/user' });

    expect(result.status).toBe(200);
    expect(result.body).toBe('{"login":"octocat"}');
    // Only one call — no listing needed because the input is a UUID.
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe(`${BASE}/v1/vault/credentials/${id}/proxy`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${API_KEY}`);
    expect(calls[0]?.body).toEqual({ method: 'GET', path: '/user' });
  });

  it('defaults an empty request to GET /', async () => {
    const id = '66666666-6666-4666-8666-666666666666';
    const { calls } = stubFetch([{ body: { status: 200, headers: {}, body: '' } }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    await aa.proxy(id);
    expect(calls[0]?.body).toEqual({ method: 'GET', path: '/' });
  });
});

describe('AgentAuthClient.proxy by target', () => {
  it('resolves a non-UUID target via listing, then proxies the matched id', async () => {
    const list: Page<VaultCredential> = {
      items: [
        { id: 'cA', target: 'gitlab.com', label: 'GL', type: 'api_key', metadata: {}, expiresAt: null },
        { id: 'cB', target: 'github.com', label: 'GH', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 2, returned: 2 },
    };
    const proxyResp = { status: 201, headers: {}, body: 'ok' };
    const { calls } = stubFetch([{ body: list }, { body: proxyResp }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.proxy('github.com', { method: 'POST', path: '/repos', body: '{}' });

    expect(result.status).toBe(201);
    expect(calls).toHaveLength(2);
    // First call lists; second proxies the matched id (cB), not the target.
    expect(calls[0]?.url).toContain('/v1/vault/credentials?limit=200');
    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/proxy`);
    expect(calls[1]?.body).toEqual({ method: 'POST', path: '/repos', body: '{}' });
  });
});

describe('AgentAuthClient.proxy approval-pending (202)', () => {
  it('throws a typed ApprovalPendingError instead of a bogus result', async () => {
    const id = '77777777-7777-4777-8777-777777777777';
    stubFetch([{ status: 202, body: { status: 'pending', requestId: 'req-42' } }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const err = await aa.proxy(id, { path: '/user' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalPendingError);
    const e = err as ApprovalPendingError;
    expect(e.status).toBe(202);
    expect(e.code).toBe('approval_pending');
    expect(e.requestId).toBe('req-42');
    expect(e.isApprovalPending).toBe(true);
  });
});

// --- AgentAuthClient: target resolution -------------------------------------

describe('AgentAuthClient.useCredential approval-pending (202)', () => {
  it('throws a typed ApprovalPendingError instead of a bogus result', async () => {
    const id = '33333333-3333-4333-8333-333333333333';
    stubFetch([{ status: 202, body: { status: 'pending', requestId: 'req-9', message: 'awaiting approval' } }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    await expect(aa.useCredential(id)).rejects.toBeInstanceOf(ApprovalPendingError);
    try {
      await aa.useCredential(id);
    } catch (e) {
      const err = e as ApprovalPendingError;
      expect(err.status).toBe(202);
      expect(err.code).toBe('approval_pending');
      expect(err.requestId).toBe('req-9');
      expect(err.isApprovalPending).toBe(true);
    }
  });
});

describe('AgentAuthClient.useCredential by target', () => {
  it('resolves a non-UUID target via listing, then uses the matched id', async () => {
    const list: Page<VaultCredential> = {
      items: [
        { id: 'cA', target: 'gitlab.com', label: 'GL', type: 'api_key', metadata: {}, expiresAt: null },
        { id: 'cB', target: 'github.com', label: 'GH', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 2, returned: 2 },
    };
    const used: UsedCredential = {
      id: 'cB',
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'ghp_resolved',
    };
    const { calls } = stubFetch([{ body: list }, { body: used }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.useCredential('github.com');

    expect(result.secret).toBe('ghp_resolved');
    expect(calls).toHaveLength(2);
    // First call lists; second uses the matched id (cB), not the target.
    expect(calls[0]?.url).toContain('/v1/vault/credentials?limit=200');
    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/use`);
  });

  it('resolves a target case-insensitively (server stores targets lowercased)', async () => {
    const list: Page<VaultCredential> = {
      items: [
        { id: 'cB', target: 'github.com', label: 'GH', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
    };
    const used: UsedCredential = {
      id: 'cB',
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'ghp_resolved',
    };
    const { calls } = stubFetch([{ body: list }, { body: used }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    // Caller passes a mixed-case host; it must still match the lowercased listing.
    const result = await aa.useCredential('GitHub.COM');
    expect(result.secret).toBe('ghp_resolved');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/use`);
  });

  it('resolves a target with a trailing dot / surrounding whitespace (deposit canonicalization)', async () => {
    const list: Page<VaultCredential> = {
      items: [
        { id: 'cB', target: 'github.com', label: 'GH', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
    };
    const used: UsedCredential = {
      id: 'cB',
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'ghp_resolved',
    };
    const { calls } = stubFetch([{ body: list }, { body: used }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.useCredential('  GitHub.com.  ');
    expect(result.secret).toBe('ghp_resolved');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/use`);
  });

  it('resolves a bare host against a URL-form stored target (host-reduced match)', async () => {
    const list: Page<VaultCredential> = {
      items: [
        {
          id: 'cB',
          target: 'https://api.github.com/v1',
          label: 'GH',
          type: 'api_key',
          metadata: {},
          expiresAt: null,
        },
      ],
      pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
    };
    const used: UsedCredential = {
      id: 'cB',
      target: 'https://api.github.com/v1',
      label: 'GH',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'ghp_resolved',
    };
    const { calls } = stubFetch([{ body: list }, { body: used }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    // The server authorizes/lists this credential by host, so the bare host resolves.
    const result = await aa.useCredential('api.github.com');
    expect(result.secret).toBe('ghp_resolved');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/use`);
  });

  it('pages through the listing until it finds a match on a later page', async () => {
    const pageOne: Page<VaultCredential> = {
      items: [
        { id: 'c1', target: 'a.com', label: 'a', type: 'api_key', metadata: {}, expiresAt: null },
        { id: 'c2', target: 'b.com', label: 'b', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 3, returned: 2 },
    };
    const pageTwo: Page<VaultCredential> = {
      items: [
        { id: 'c3', target: 'target.com', label: 't', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 2, total: 3, returned: 1 },
    };
    const used: UsedCredential = {
      id: 'c3',
      target: 'target.com',
      label: 't',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
      secret: 'found-on-page-2',
    };
    const { calls } = stubFetch([{ body: pageOne }, { body: pageTwo }, { body: used }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.useCredential('target.com');

    expect(result.secret).toBe('found-on-page-2');
    expect(calls).toHaveLength(3);
    expect(calls[1]?.url).toContain('offset=2');
    expect(calls[2]?.url).toBe(`${BASE}/v1/vault/credentials/c3/use`);
  });

  it('throws a 404 AgentAuthError when no credential matches the target', async () => {
    const empty: Page<VaultCredential> = {
      items: [
        { id: 'cX', target: 'other.com', label: 'o', type: 'api_key', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
    };
    stubFetch([{ body: empty }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    await expect(aa.useCredential('missing.com')).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    });
  });

  it('does not call /use when the listing is empty', async () => {
    const empty: Page<VaultCredential> = {
      items: [],
      pagination: { limit: 200, offset: 0, total: 0, returned: 0 },
    };
    const { calls } = stubFetch([{ body: empty }]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    await expect(aa.useCredential('whatever.com')).rejects.toBeInstanceOf(AgentAuthError);
    expect(calls).toHaveLength(1); // only the listing call
  });
});

// --- Error mapping ----------------------------------------------------------

describe('error mapping', () => {
  it('maps the server error envelope onto AgentAuthError fields', async () => {
    stubFetch([
      {
        status: 403,
        body: {
          error: {
            code: 'forbidden',
            message: 'agent not scoped for target',
            requestId: 'req-123',
            details: { target: 'github.com' },
          },
        },
      },
    ]);

    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const err = await aa
      .useCredential('33333333-3333-4333-8333-333333333333')
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(AgentAuthError);
    const e = err as AgentAuthError;
    expect(e.status).toBe(403);
    expect(e.code).toBe('forbidden');
    expect(e.message).toBe('agent not scoped for target');
    expect(e.requestId).toBe('req-123');
    expect(e.details).toEqual({ target: 'github.com' });
    expect(e.isForbidden).toBe(true);
    expect(e.isUnauthorized).toBe(false);
  });

  it.each([
    [401, 'isUnauthorized'],
    [403, 'isForbidden'],
    [404, 'isNotFound'],
    [410, 'isGone'],
    [429, 'isRateLimited'],
    [503, 'isUnavailable'],
  ] as const)('distinguishes status %i via its boolean accessor', async (status, flag) => {
    stubFetch([{ status, body: { error: { code: 'x', message: 'm' } } }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const e = (await aa
      .useCredential('44444444-4444-4444-8444-444444444444')
      .catch((x: unknown) => x)) as AgentAuthError;
    expect(e.status).toBe(status);
    expect(e[flag]).toBe(true);
  });

  it('falls back to a default code/message when the body is missing or malformed', async () => {
    stubFetch([{ status: 410, text: '<html>not json</html>' }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const e = (await aa
      .useCredential('55555555-5555-4555-8555-555555555555')
      .catch((x: unknown) => x)) as AgentAuthError;
    expect(e.status).toBe(410);
    expect(e.code).toBe('gone'); // derived from status, no envelope present
    expect(e.message).toContain('410');
  });

  it('surfaces a network failure as status 0 / network_error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new Error('ECONNREFUSED'))),
    );
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const e = (await aa.listCredentials().catch((x: unknown) => x)) as AgentAuthError;
    expect(e).toBeInstanceOf(AgentAuthError);
    expect(e.status).toBe(0);
    expect(e.code).toBe('network_error');
    expect(e.message).toContain('ECONNREFUSED');
  });
});

// --- Construction guards ----------------------------------------------------

describe('construction', () => {
  it('requires baseUrl', () => {
    expect(() => new AgentAuthClient({ baseUrl: '', apiKey: API_KEY })).toThrow(/baseUrl/);
  });
  it('requires apiKey for AgentAuthClient', () => {
    expect(() => new AgentAuthClient({ baseUrl: BASE, apiKey: '' })).toThrow(/apiKey/);
  });
  it('requires token for HumanClient', () => {
    expect(() => new HumanClient({ baseUrl: BASE, token: '' })).toThrow(/token/);
  });
});

// --- HumanClient ------------------------------------------------------------

describe('HumanClient.login', () => {
  it('POSTs credentials and returns a client wired with the session token', async () => {
    const { calls } = stubFetch([
      { body: { token: TOKEN, tokenType: 'Bearer', expiresAt: '2099-01-01T00:00:00Z' } },
      { body: { id: 'p1', name: 'work', createdAt: '2026-01-01T00:00:00Z' } },
    ]);

    const human = await HumanClient.login(BASE, 'me@example.com', 'pw');
    // The login call carries no auth header and posts the credentials.
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/login`);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.body).toEqual({ email: 'me@example.com', password: 'pw' });
    expect(calls[0]?.headers.authorization).toBeUndefined();

    // A subsequent call uses the bearer token from login.
    await human.createPassport('work');
    expect(calls[1]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[1]?.body).toEqual({ name: 'work' });
  });

  it('throws AgentAuthError on bad credentials (401)', async () => {
    stubFetch([{ status: 401, body: { error: { code: 'unauthorized', message: 'nope' } } }]);
    const e = (await HumanClient.login(BASE, 'me@example.com', 'wrong').catch(
      (x: unknown) => x,
    )) as AgentAuthError;
    expect(e.status).toBe(401);
    expect(e.isUnauthorized).toBe(true);
  });
});

describe('HumanClient admin operations', () => {
  function client() {
    return new HumanClient({ baseUrl: BASE, token: TOKEN });
  }

  it('depositCredential POSTs the full body to the passport credentials path', async () => {
    const { calls } = stubFetch([
      {
        status: 201,
        body: {
          id: 'cred1',
          target: 'github.com',
          label: 'GH',
          type: 'api_key',
          metadata: {},
          expiresAt: null,
          createdAt: '2026-01-01T00:00:00Z',
        },
      },
    ]);
    const created = await client().depositCredential('p1', {
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      secret: 'ghp_x',
    });
    expect(created.id).toBe('cred1');
    expect(calls[0]?.url).toBe(`${BASE}/v1/passports/p1/credentials`);
    expect(calls[0]?.body).toMatchObject({ target: 'github.com', secret: 'ghp_x' });
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('issueAgent returns the one-time apiKey', async () => {
    const { calls } = stubFetch([
      {
        status: 201,
        body: {
          id: 'a1',
          name: 'ci-bot',
          scopes: ['vault:read', 'vault:use', 'target:github.com'],
          apiKey: 'aa_xxx.yyy',
          warning: 'shown once',
        },
      },
    ]);
    const agent = await client().issueAgent({
      passportId: 'p1',
      name: 'ci-bot',
      scopes: ['vault:read', 'vault:use', 'target:github.com'],
    });
    expect(agent.apiKey).toBe('aa_xxx.yyy');
    expect(calls[0]?.url).toBe(`${BASE}/v1/agents`);
    expect(calls[0]?.body).toMatchObject({ passportId: 'p1', name: 'ci-bot' });
  });

  it('revokeAgent POSTs to the revoke path', async () => {
    const { calls } = stubFetch([{ body: { id: 'a1', revoked: true } }]);
    const res = await client().revokeAgent('a1');
    expect(res.revoked).toBe(true);
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe(`${BASE}/v1/agents/a1/revoke`);
  });

  it('listPassports / listAudit pass pagination through', async () => {
    const { calls } = stubFetch([
      { body: { items: [], pagination: { limit: 10, offset: 5, total: 0, returned: 0 } } },
      { body: { items: [], pagination: { limit: 10, offset: 0, total: 0, returned: 0 } } },
    ]);
    const c = client();
    await c.listPassports({ limit: 10, offset: 5 });
    await c.listAudit({ limit: 10 });
    expect(calls[0]?.url).toBe(`${BASE}/v1/passports?limit=10&offset=5`);
    expect(calls[1]?.url).toBe(`${BASE}/v1/audit?limit=10`);
  });

  it('verifyAudit GETs the verify endpoint', async () => {
    const { calls } = stubFetch([{ body: { ok: true } }]);
    const res = await client().verifyAudit();
    expect(res.ok).toBe(true);
    expect(calls[0]?.url).toBe(`${BASE}/v1/audit/verify`);
  });

  it('register (static) POSTs to /v1/principals without auth', async () => {
    const { calls } = stubFetch([{ status: 201, body: { id: 'pr1', email: 'me@example.com' } }]);
    const principal = await HumanClient.register(BASE, 'me@example.com', 'pw');
    expect(principal.id).toBe('pr1');
    expect(calls[0]?.url).toBe(`${BASE}/v1/principals`);
    expect(calls[0]?.headers.authorization).toBeUndefined();
  });

  it('logout POSTs with the bearer token', async () => {
    const { calls } = stubFetch([{ body: { loggedOut: true } }]);
    const res = await client().logout();
    expect(res.loggedOut).toBe(true);
    expect(calls[0]?.url).toBe(`${BASE}/v1/auth/logout`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });
});

describe('HumanClient approval methods', () => {
  it('lists, approves, and denies via the right routes', async () => {
    const { calls } = stubFetch([
      { status: 200, body: { items: [], pagination: { limit: 50, offset: 0, total: 0, returned: 0 } } },
      { status: 200, body: { id: 'r1', status: 'approved' } },
      { status: 200, body: { id: 'r1', status: 'denied' } },
    ]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    await hc.listApprovals();
    await hc.approveRequest('r1');
    await hc.denyRequest('r1');
    expect(calls[0]?.url).toBe(`${BASE}/v1/approvals`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[1]?.method).toBe('POST');
    expect(calls[1]?.url).toBe(`${BASE}/v1/approvals/r1/approve`);
    expect(calls[2]?.url).toBe(`${BASE}/v1/approvals/r1/deny`);
  });
});

// --- HumanClient: deposit policy fields, mTLS bind, OAuth start --------------

describe('HumanClient.depositCredential policy fields', () => {
  it('forwards maxUses/allowedFrom/allowedUntil/requireApproval only when set', async () => {
    const { calls } = stubFetch([
      {
        status: 201,
        body: {
          id: 'cred1',
          target: 'github.com',
          label: 'GH',
          type: 'api_key',
          metadata: {},
          expiresAt: null,
          createdAt: '2026-01-01T00:00:00Z',
        },
      },
    ]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    await hc.depositCredential('p1', {
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      secret: 'ghp_x',
      maxUses: 5,
      allowedFrom: '2026-01-01T00:00:00Z',
      allowedUntil: '2026-12-31T00:00:00Z',
      requireApproval: true,
    });
    expect(calls[0]?.url).toBe(`${BASE}/v1/passports/p1/credentials`);
    expect(calls[0]?.body).toMatchObject({
      target: 'github.com',
      secret: 'ghp_x',
      maxUses: 5,
      allowedFrom: '2026-01-01T00:00:00Z',
      allowedUntil: '2026-12-31T00:00:00Z',
      requireApproval: true,
    });
  });

  it('omits policy fields entirely when not provided', async () => {
    const { calls } = stubFetch([
      {
        status: 201,
        body: {
          id: 'cred1',
          target: 'github.com',
          label: 'GH',
          type: 'api_key',
          metadata: {},
          expiresAt: null,
          createdAt: '2026-01-01T00:00:00Z',
        },
      },
    ]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    await hc.depositCredential('p1', {
      target: 'github.com',
      label: 'GH',
      type: 'api_key',
      secret: 'ghp_x',
    });
    const body = calls[0]?.body as Record<string, unknown>;
    expect(body).not.toHaveProperty('maxUses');
    expect(body).not.toHaveProperty('allowedFrom');
    expect(body).not.toHaveProperty('allowedUntil');
    expect(body).not.toHaveProperty('requireApproval');
  });
});

describe('HumanClient.bindAgentMtls', () => {
  it('POSTs the mtls path with a fingerprint and returns the binding', async () => {
    const fp = 'a'.repeat(64);
    const { calls } = stubFetch([{ status: 200, body: { id: 'a1', certFingerprint: fp } }]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    const res = await hc.bindAgentMtls('a1', { fingerprint: fp });
    expect(res).toEqual({ id: 'a1', certFingerprint: fp });
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe(`${BASE}/v1/agents/a1/mtls`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]?.body).toEqual({ fingerprint: fp });
  });

  it('forwards certPem and omits unset fields', async () => {
    const { calls } = stubFetch([{ status: 200, body: { id: 'a1', certFingerprint: 'b'.repeat(64) } }]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    await hc.bindAgentMtls('a1', { certPem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----' });
    expect(calls[0]?.body).toEqual({
      certPem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----',
    });
  });
});

describe('HumanClient.startOauth', () => {
  it('POSTs the start path and returns authorizeUrl + state', async () => {
    const { calls } = stubFetch([
      { status: 200, body: { authorizeUrl: 'https://github.com/login/oauth/authorize?x=1', state: 'st-1' } },
    ]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    const res = await hc.startOauth('p1', 'github', { target: 'api.github.com', label: 'gh oauth' });
    expect(res).toEqual({
      authorizeUrl: 'https://github.com/login/oauth/authorize?x=1',
      state: 'st-1',
    });
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toBe(`${BASE}/v1/passports/p1/oauth/github/start`);
    expect(calls[0]?.body).toEqual({ target: 'api.github.com', label: 'gh oauth' });
  });

  it('sends an empty body when no opts are passed', async () => {
    const { calls } = stubFetch([{ status: 200, body: { authorizeUrl: 'https://x/y', state: 's' } }]);
    const hc = new HumanClient({ baseUrl: BASE, token: TOKEN });
    await hc.startOauth('p1', 'google');
    expect(calls[0]?.url).toBe(`${BASE}/v1/passports/p1/oauth/google/start`);
    expect(calls[0]?.body).toEqual({});
  });
});

// --- AgentAuthClient: browser-login -----------------------------------------

const PLAN_UUID = '88888888-8888-4888-8888-888888888888';

describe('AgentAuthClient.getBrowserLoginPlan', () => {
  it('POSTs straight to the browser-login path for a UUID', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'header',
      target: 'github.com',
      url: 'https://github.com',
      headers: { authorization: 'Bearer ghp_secret' },
    };
    const { calls } = stubFetch([{ body: plan }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.getBrowserLoginPlan(PLAN_UUID);
    expect(result.mode).toBe('header');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe('POST');
    // The liability path hits the raw endpoint (?raw=true → vault:browser:raw).
    expect(calls[0]?.url).toBe(`${BASE}/v1/vault/credentials/${PLAN_UUID}/browser-login?raw=true`);
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${API_KEY}`);
  });

  it('resolves a non-UUID target via listing, then POSTs the matched id', async () => {
    const list: Page<VaultCredential> = {
      items: [
        { id: 'cB', target: 'github.com', label: 'GH', type: 'cookie', metadata: {}, expiresAt: null },
      ],
      pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
    };
    const plan: BrowserLoginPlan = {
      mode: 'cookie',
      target: 'github.com',
      url: 'https://github.com',
      cookies: [{ name: 'session', value: 'sekret', path: '/' }],
    };
    const { calls } = stubFetch([{ body: list }, { body: plan }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const result = await aa.getBrowserLoginPlan('github.com');
    expect(result.mode).toBe('cookie');
    expect(calls).toHaveLength(2);
    expect(calls[0]?.url).toContain('/v1/vault/credentials?limit=200');
    expect(calls[1]?.url).toBe(`${BASE}/v1/vault/credentials/cB/browser-login?raw=true`);
  });

  it('throws ApprovalPendingError on a 202', async () => {
    stubFetch([{ status: 202, body: { status: 'pending', requestId: 'req-bl' } }]);
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const err = await aa.getBrowserLoginPlan(PLAN_UUID).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalPendingError);
    expect((err as ApprovalPendingError).requestId).toBe('req-bl');
  });
});

// A FakePage that records every interaction, modelling Playwright's shape
// (context().addCookies / setExtraHTTPHeaders, fill) with an opt-in Puppeteer mode.
interface PageEvent {
  kind: string;
  arg?: unknown;
}

function makeFakePage(
  opts: { puppeteer?: boolean; currentUrl?: string; html?: string; postSubmitUrl?: string } = {},
): {
  page: BrowserPage;
  events: PageEvent[];
  store: Record<string, string>;
} {
  const events: PageEvent[] = [];
  const store: Record<string, string> = {};
  let current = opts.currentUrl ?? '';

  const page: BrowserPage = {
    goto: (url: string) => {
      current = url;
      events.push({ kind: 'goto', arg: url });
      return Promise.resolve(null);
    },
    content: () => Promise.resolve(opts.html ?? ''),
    evaluate: <R, A>(fn: (arg: A) => R, arg: A): Promise<R> => {
      // Simulate the localStorage seeding by running the fn against a shim.
      events.push({ kind: 'evaluate', arg });
      const g = globalThis as unknown as { localStorage?: unknown };
      const had = g.localStorage;
      g.localStorage = { setItem: (k: string, v: string) => void (store[k] = v) };
      try {
        const r = fn(arg);
        return Promise.resolve(r);
      } finally {
        g.localStorage = had;
      }
    },
    click: (selector: string) => {
      events.push({ kind: 'click', arg: selector });
      // Simulate the post-submit navigation (success or MFA redirect) if given.
      if (opts.postSubmitUrl !== undefined) current = opts.postSubmitUrl;
      return Promise.resolve(null);
    },
    url: () => current,
  };

  if (opts.puppeteer) {
    page.setCookie = (...cookies: PlanCookie[]) => {
      events.push({ kind: 'setCookie', arg: cookies });
      return Promise.resolve(null);
    };
    page.setExtraHTTPHeaders = (headers: Record<string, string>) => {
      events.push({ kind: 'setExtraHTTPHeaders', arg: headers });
      return Promise.resolve(null);
    };
    page.type = (selector: string, value: string) => {
      events.push({ kind: 'type', arg: { selector, value } });
      return Promise.resolve(null);
    };
  } else {
    page.context = () =>
      ({
        addCookies: (cookies: PlanCookie[]) => {
          events.push({ kind: 'addCookies', arg: cookies });
          return Promise.resolve(null);
        },
        setExtraHTTPHeaders: (headers: Record<string, string>) => {
          events.push({ kind: 'ctxSetHeaders', arg: headers });
          return Promise.resolve(null);
        },
        clearCookies: () => {
          events.push({ kind: 'clearCookies', arg: null });
          return Promise.resolve(null);
        },
      }) as ReturnType<NonNullable<BrowserPage['context']>>;
    page.fill = (selector: string, value: string) => {
      events.push({ kind: 'fill', arg: { selector, value } });
      return Promise.resolve(null);
    };
  }
  return { page, events, store };
}

/** Recursively assert no secret string appears anywhere in a value. */
function assertNoSecret(value: unknown, secrets: string[]): void {
  const json = JSON.stringify(value);
  for (const s of secrets) {
    expect(json).not.toContain(s);
  }
}

describe('applyBrowserLogin / browserLogin', () => {
  it('cookie mode (Playwright): adds cookies then navigates; summary has no secret', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'cookie',
      target: 'github.com',
      url: 'https://github.com/dashboard',
      cookies: [
        { name: 'session', value: 'SECRET_COOKIE', domain: 'github.com', path: '/', secure: true },
      ],
    };
    const { page, events } = makeFakePage();
    const summary = await applyBrowserLogin(page, plan);
    expect(events.map((e) => e.kind)).toEqual(['addCookies', 'goto']);
    expect((events[1] as PageEvent).arg).toBe('https://github.com/dashboard');
    expect(summary).toEqual({
      mode: 'cookie',
      target: 'github.com',
      url: 'https://github.com/dashboard',
      authenticated: true,
      cookieNames: ['session'],
    });
    assertNoSecret(summary, ['SECRET_COOKIE']);
  });

  it('cookie mode (Puppeteer): uses page.setCookie spread', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'cookie',
      target: 'github.com',
      url: 'https://github.com',
      cookies: [{ name: 'a', value: 'SECRET_A', path: '/' }, { name: 'b', value: 'SECRET_B', path: '/' }],
    };
    const { page, events } = makeFakePage({ puppeteer: true });
    const summary = await applyBrowserLogin(page, plan);
    expect(events[0]?.kind).toBe('setCookie');
    expect((events[0]?.arg as PlanCookie[]).map((c) => c.name)).toEqual(['a', 'b']);
    expect(summary.cookieNames).toEqual(['a', 'b']);
    assertNoSecret(summary, ['SECRET_A', 'SECRET_B']);
  });

  it('header mode (Playwright): sets headers on the context then navigates', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'header',
      target: 'api.example.com',
      url: 'https://api.example.com',
      headers: { authorization: 'Bearer SECRET_TOKEN', 'x-api-key': 'SECRET_KEY' },
    };
    const { page, events } = makeFakePage();
    const summary = await applyBrowserLogin(page, plan);
    expect(events.map((e) => e.kind)).toEqual(['ctxSetHeaders', 'goto']);
    expect(summary).toEqual({
      mode: 'header',
      target: 'api.example.com',
      url: 'https://api.example.com',
      authenticated: true,
      headerNames: ['authorization', 'x-api-key'],
    });
    assertNoSecret(summary, ['SECRET_TOKEN', 'SECRET_KEY']);
  });

  it('localStorage mode: navigates then seeds storage; summary lists keys only', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'localStorage',
      target: 'app.example.com',
      origin: 'https://app.example.com',
      url: 'https://app.example.com',
      items: { token: 'SECRET_LS', refresh: 'SECRET_RS' },
    };
    const { page, events, store } = makeFakePage();
    const summary = await applyBrowserLogin(page, plan);
    expect(events.map((e) => e.kind)).toEqual(['goto', 'evaluate']);
    expect(store.token).toBe('SECRET_LS'); // applied into the page
    expect(summary).toEqual({
      mode: 'localStorage',
      target: 'app.example.com',
      url: 'https://app.example.com',
      authenticated: true,
      storageKeys: ['token', 'refresh'],
    });
    assertNoSecret(summary, ['SECRET_LS', 'SECRET_RS']);
  });

  it('form mode (Playwright): runs goto/fill/click in order and detects success', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      actions: [
        { type: 'goto', url: 'https://site.example.com/login' },
        { type: 'fill', selector: '#user', value: 'alice' },
        { type: 'fill', selector: '#pass', value: 'SECRET_PW' },
        { type: 'click', selector: '#submit' },
        { type: 'goto', url: 'https://site.example.com/home' },
      ],
      successUrlIncludes: '/home',
    };
    const { page, events } = makeFakePage();
    const summary = await applyBrowserLogin(page, plan);
    expect(events.map((e) => e.kind)).toEqual(['goto', 'fill', 'fill', 'click', 'goto']);
    expect(summary).toEqual({
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      authenticated: true,
      filledFields: 2,
      submitted: true,
    });
    assertNoSecret(summary, ['SECRET_PW', 'alice']);
  });

  it('form mode (Puppeteer): uses page.type when fill is absent', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      actions: [{ type: 'fill', selector: '#pass', value: 'SECRET_PW' }],
    };
    const { page, events } = makeFakePage({ puppeteer: true });
    const summary = await applyBrowserLogin(page, plan);
    expect(events[0]?.kind).toBe('type');
    expect(summary.filledFields).toBe(1);
    expect(summary).not.toHaveProperty('submitted');
    assertNoSecret(summary, ['SECRET_PW']);
  });

  it('browserLogin fetches the plan then applies it', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'cookie',
      target: 'github.com',
      url: 'https://github.com',
      cookies: [{ name: 'session', value: 'SECRET_COOKIE', path: '/' }],
    };
    const { calls } = stubFetch([{ body: plan }]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const summary = await aa.browserLogin(page, PLAN_UUID);
    expect(calls[0]?.url).toBe(`${BASE}/v1/vault/credentials/${PLAN_UUID}/browser-login`);
    expect(events.map((e) => e.kind)).toEqual(['addCookies', 'goto']);
    expect(summary.authenticated).toBe(true);
    expect(summary.cookieNames).toEqual(['session']);
    assertNoSecret(summary, ['SECRET_COOKIE']);
  });

  it('form mode: detects an MFA challenge by URL and returns it (non-secret)', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      actions: [
        { type: 'fill', selector: '#user', value: 'alice' },
        { type: 'fill', selector: '#pass', value: 'SECRET_PW' },
        { type: 'click', selector: '#submit' },
      ],
      successUrlIncludes: '/dashboard',
      mfa: { kind: 'totp', channelHint: 'code from your authenticator app' },
    };
    const { page } = makeFakePage({
      postSubmitUrl: 'https://site.example.com/mfa/challenge',
      html: '<form><input type="password"></form>',
    });
    const summary = await applyBrowserLogin(page, plan);
    expect(summary.authenticated).toBe(false);
    expect(summary.mfa?.kind).toBe('totp');
    expect(summary.mfa?.promptText).toBe('code from your authenticator app');
    expect(typeof summary.mfa?.challengeId).toBe('string');
    expect(typeof summary.mfa?.detectedAt).toBe('string');
    assertNoSecret(summary, ['SECRET_PW', 'alice']);
  });

  it('form mode: detects an MFA challenge by page text + input when the URL is unremarkable', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      actions: [
        { type: 'fill', selector: '#pass', value: 'SECRET_PW' },
        { type: 'click', selector: '#go' },
      ],
      successUrlIncludes: '/home',
    };
    const html =
      '<h1>Verification code</h1><p>Enter the 6-digit code sent to ' +
      '•••1234</p><input autocomplete="one-time-code">';
    const { page } = makeFakePage({ postSubmitUrl: 'https://site.example.com/step2', html });
    const summary = await applyBrowserLogin(page, plan);
    expect(summary.authenticated).toBe(false);
    expect(summary.mfa).toBeDefined();
    expect(summary.mfa?.kind).toBe('otp'); // default when spec omits kind
    expect(summary.mfa?.promptText.toLowerCase()).toContain('code');
  });

  it('form mode: reaching successUrlIncludes is authenticated with no mfa', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'site.example.com',
      url: 'https://site.example.com/login',
      actions: [
        { type: 'fill', selector: '#pass', value: 'SECRET_PW' },
        { type: 'click', selector: '#go' },
      ],
      successUrlIncludes: '/dashboard',
    };
    const { page } = makeFakePage({ postSubmitUrl: 'https://site.example.com/dashboard' });
    const summary = await applyBrowserLogin(page, plan);
    expect(summary.authenticated).toBe(true);
    expect(summary.mfa).toBeUndefined();
    expect(summary.submitted).toBe(true);
  });
});

describe('AgentAuthClient.resolveMfa', () => {
  const challenge: MfaChallenge = {
    kind: 'totp',
    promptText: 'enter the code',
    detectedAt: '2026-01-01T00:00:00Z',
    challengeId: 'ch1',
  };
  const noSleep = () => Promise.resolve();

  it('opens a request, polls, injects the approved code into the DOM, returns a non-secret resolution', async () => {
    const { calls } = stubFetch([
      { body: { requestId: 'req-1', status: 'pending' } }, // POST /mfa/request
      { body: { status: 'pending' } }, // GET poll 1
      { body: { status: 'approved', code: '123456', by: 'owner@example.com', at: '2026-01-01T00:01:00Z' } },
    ]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const res = await aa.resolveMfa(page, PLAN_UUID, challenge, {
      inputSelector: '#otp',
      submitSelector: '#verify',
      sleep: noSleep,
    });

    expect(res.resolved).toBe(true);
    expect(res.status).toBe('approved');
    expect(res.by).toBe('owner@example.com');
    // The code went into the DOM (fill) but NOT into the resolution.
    const fill = events.find((e) => e.kind === 'fill');
    expect((fill?.arg as { selector: string }).selector).toBe('#otp');
    expect(events.some((e) => e.kind === 'click')).toBe(true);
    assertNoSecret(res, ['123456']);
    // POST /mfa/request first, then GET polls.
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.url).toContain(`/v1/vault/credentials/${PLAN_UUID}/mfa/request`);
    expect(calls[1]?.url).toContain('/mfa/request/req-1');
  });

  it('returns denied without injecting anything', async () => {
    stubFetch([{ body: { requestId: 'r', status: 'pending' } }, { body: { status: 'denied' } }]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const res = await aa.resolveMfa(page, PLAN_UUID, challenge, { inputSelector: '#otp', sleep: noSleep });
    expect(res.resolved).toBe(false);
    expect(res.status).toBe('denied');
    expect(events.find((e) => e.kind === 'fill')).toBeUndefined();
  });

  it('maps a 410 poll (expired/consumed) to expired', async () => {
    stubFetch([
      { body: { requestId: 'r', status: 'pending' } },
      { status: 410, body: { error: { code: 'expired', message: 'gone' } } },
    ]);
    const { page } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const res = await aa.resolveMfa(page, PLAN_UUID, challenge, { inputSelector: '#otp', sleep: noSleep });
    expect(res.resolved).toBe(false);
    expect(res.status).toBe('expired');
  });

  it('reports resolved:false when an approved code has no selector to inject into', async () => {
    stubFetch([
      { body: { requestId: 'r', status: 'pending' } },
      { body: { status: 'approved', code: '123456', by: 'o@e.com', at: 't' } },
    ]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    // No inputSelector in opts AND the challenge carries none -> can't apply.
    const res = await aa.resolveMfa(page, PLAN_UUID, challenge, { sleep: noSleep });
    expect(res.resolved).toBe(false);
    expect(res.status).toBe('approved');
    expect(events.find((e) => e.kind === 'fill')).toBeUndefined();
  });

  it('reports resolved:false (and does not submit) when the page can neither fill nor type', async () => {
    stubFetch([
      { body: { requestId: 'r', status: 'pending' } },
      { body: { status: 'approved', code: '123456', by: 'o@e.com', at: 't' } },
    ]);
    const clicks: string[] = [];
    const page = {
      goto: () => Promise.resolve(null),
      evaluate: () => Promise.resolve(null),
      click: (s: string) => {
        clicks.push(s);
        return Promise.resolve(null);
      },
      url: () => '',
    } as unknown as BrowserPage;
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const res = await aa.resolveMfa(page, PLAN_UUID, challenge, {
      inputSelector: '#otp',
      submitSelector: '#go',
      sleep: noSleep,
    });
    expect(res.resolved).toBe(false);
    expect(res.status).toBe('approved');
    expect(clicks).toHaveLength(0); // never submitted an empty field
  });

  it('falls back to the challenge inputSelector/submitSelector when no opt is given', async () => {
    stubFetch([
      { body: { requestId: 'r', status: 'pending' } },
      { body: { status: 'approved', code: '123456', by: 'o@e.com', at: 't' } },
    ]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    const ch: MfaChallenge = { ...challenge, inputSelector: '#otp', submitSelector: '#verify' };
    const res = await aa.resolveMfa(page, PLAN_UUID, ch, { sleep: noSleep });
    expect(res.resolved).toBe(true);
    expect((events.find((e) => e.kind === 'fill')?.arg as { selector: string }).selector).toBe('#otp');
  });
});

describe('browser hardening (Phase 4)', () => {
  it('form mode: refuses navigation to a host outside allowedDomains', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'app.example.com',
      url: 'https://app.example.com/login',
      actions: [{ type: 'goto', url: 'https://evil.example.org/login' }],
      allowedDomains: ['app.example.com'],
    };
    const { page } = makeFakePage();
    await expect(applyBrowserLogin(page, plan)).rejects.toThrow(/allowedDomains/);
  });

  it('form mode: allows a subdomain within allowedDomains (*.example.com)', async () => {
    const plan: BrowserLoginPlan = {
      mode: 'form',
      target: 'example.com',
      url: 'https://app.example.com/login',
      actions: [
        { type: 'goto', url: 'https://app.example.com/login' },
        { type: 'fill', selector: '#p', value: 'SECRET' },
      ],
      allowedDomains: ['*.example.com'],
    };
    const { page } = makeFakePage();
    const summary = await applyBrowserLogin(page, plan);
    expect(summary.filledFields).toBe(1);
    expect(summary.authenticated).toBe(true);
  });

  it('browserLogin force-logs-out the browser when the agent is revoked (401)', async () => {
    stubFetch([{ status: 401, body: { error: { code: 'unauthorized', message: 'revoked' } } }]);
    const { page, events } = makeFakePage();
    const aa = new AgentAuthClient({ baseUrl: BASE, apiKey: API_KEY });
    await expect(aa.browserLogin(page, PLAN_UUID)).rejects.toMatchObject({ status: 401 });
    expect(events.some((e) => e.kind === 'clearCookies')).toBe(true);
    expect(events.some((e) => e.kind === 'goto' && e.arg === 'about:blank')).toBe(true);
  });
});
