import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AgentAuthClient,
  AgentAuthError,
  ApprovalPendingError,
  HumanClient,
  type Page,
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
