import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  api,
  ApiError,
  getToken,
  setToken,
  clearToken,
  isAuthenticated,
  API_URL,
} from './api';

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

type MockResponseInit = {
  status?: number;
  body?: unknown;
  /** When true, send a non-JSON text body. */
  rawText?: string;
};

function mockFetchOnce({ status = 200, body, rawText }: MockResponseInit) {
  const text =
    rawText !== undefined
      ? rawText
      : body !== undefined
      ? JSON.stringify(body)
      : '';
  const res = {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status ${status}`,
    text: async () => text,
  } as unknown as Response;
  // Typed params so `fn.mock.calls[i]` is a [url, init?] tuple, not [].
  const fn = vi.fn(async (_url: string, _init?: RequestInit) => res);
  vi.stubGlobal('fetch', fn);
  return fn;
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

describe('token storage', () => {
  it('round-trips a token through localStorage', () => {
    expect(getToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);

    setToken('jwt-123');
    expect(getToken()).toBe('jwt-123');
    expect(isAuthenticated()).toBe(true);

    clearToken();
    expect(getToken()).toBeNull();
    expect(isAuthenticated()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Request shaping + auth header
// ---------------------------------------------------------------------------

describe('request shaping', () => {
  it('attaches the bearer token on authed requests', async () => {
    setToken('jwt-abc');
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });

    await api.listPassports();

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/passports`);
    expect((init as RequestInit).method).toBe('GET');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['authorization']).toBe('Bearer jwt-abc');
  });

  it('omits the bearer token on unauthenticated endpoints (register)', async () => {
    setToken('jwt-should-not-leak');
    const fetchFn = mockFetchOnce({ body: { id: 'p1', email: 'a@b.c' } });

    await api.register('a@b.c', 'pw');

    const init = fetchFn.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    expect(headers['authorization']).toBeUndefined();
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ email: 'a@b.c', password: 'pw' }));
  });

  it('builds pagination query strings', async () => {
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });
    await api.listAudit(25, 50);
    expect(fetchFn.mock.calls[0][0]).toBe(
      `${API_URL}/v1/audit?limit=25&offset=50`,
    );
  });

  it('url-encodes path params', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });
    await api.listCredentials('pa ss/id');
    expect(fetchFn.mock.calls[0][0]).toBe(
      `${API_URL}/v1/passports/pa%20ss%2Fid/credentials`,
    );
  });
});

// ---------------------------------------------------------------------------
// Credential deposit — policy field forwarding
// ---------------------------------------------------------------------------

describe('depositCredential', () => {
  it('forwards the usage-policy fields in the request body', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'c1' } });

    await api.depositCredential('p1', {
      target: 'github.com',
      label: 'gh',
      type: 'api_key',
      secret: 's3cr3t',
      maxUses: 5,
      allowedFrom: '2026-01-01T00:00:00.000Z',
      allowedUntil: '2026-12-31T00:00:00.000Z',
      requireApproval: true,
      metadata: { browser: { mode: 'cookie' } },
    });

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/passports/p1/credentials`);
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toMatchObject({
      target: 'github.com',
      label: 'gh',
      type: 'api_key',
      secret: 's3cr3t',
      maxUses: 5,
      allowedFrom: '2026-01-01T00:00:00.000Z',
      allowedUntil: '2026-12-31T00:00:00.000Z',
      requireApproval: true,
      metadata: { browser: { mode: 'cookie' } },
    });
  });

  it('omits policy fields when not provided', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'c2' } });

    await api.depositCredential('p1', {
      target: 'github.com',
      label: 'gh',
      type: 'api_key',
      secret: 's',
    });

    const body = JSON.parse((fetchFn.mock.calls[0][1] as RequestInit).body as string);
    expect(body).not.toHaveProperty('maxUses');
    expect(body).not.toHaveProperty('allowedFrom');
    expect(body).not.toHaveProperty('requireApproval');
  });
});

// ---------------------------------------------------------------------------
// mTLS bind
// ---------------------------------------------------------------------------

describe('bindAgentMtls', () => {
  it('POSTs the fingerprint to the agent mtls endpoint', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({
      body: { id: 'a1', certFingerprint: 'ab'.repeat(32) },
    });

    const res = await api.bindAgentMtls('a1', { fingerprint: 'AB:'.repeat(31) + 'AB' });

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/agents/a1/mtls`);
    expect((init as RequestInit).method).toBe('POST');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toEqual({ fingerprint: 'AB:'.repeat(31) + 'AB' });
    expect(res.certFingerprint).toBe('ab'.repeat(32));
  });

  it('url-encodes the agent id', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'x', certFingerprint: 'f' } });
    await api.bindAgentMtls('a/b', { certPem: '-----BEGIN CERTIFICATE-----' });
    expect(fetchFn.mock.calls[0][0]).toBe(`${API_URL}/v1/agents/a%2Fb/mtls`);
  });
});

// ---------------------------------------------------------------------------
// MFA approval queue
// ---------------------------------------------------------------------------

describe('mfa queue', () => {
  it('listMfa builds the paged GET request', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { items: [], pagination: {} } });

    await api.listMfa(50, 10);

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/mfa?limit=50&offset=10`);
    expect((init as RequestInit).method).toBe('GET');
  });

  it('approveMfa sends a { code } body when a code is provided', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'm1', status: 'approved' } });

    const res = await api.approveMfa('m1', '123456');

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/mfa/m1/approve`);
    expect((init as RequestInit).method).toBe('POST');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toEqual({ code: '123456' });
    expect(res.status).toBe('approved');
  });

  it('approveMfa omits the body entirely when no code is provided', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'm2', status: 'approved' } });

    await api.approveMfa('m2');

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/mfa/m2/approve`);
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).body).toBeUndefined();
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers['content-type']).toBeUndefined();
  });

  it('denyMfa POSTs to the deny endpoint with no body', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'm3', status: 'denied' } });

    const res = await api.denyMfa('m3');

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe(`${API_URL}/v1/mfa/m3/deny`);
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).body).toBeUndefined();
    expect(res.status).toBe('denied');
  });

  it('url-encodes the mfa id in the action path', async () => {
    setToken('t');
    const fetchFn = mockFetchOnce({ body: { id: 'a/b', status: 'denied' } });
    await api.denyMfa('a/b');
    expect(fetchFn.mock.calls[0][0]).toBe(`${API_URL}/v1/mfa/a%2Fb/deny`);
  });
});

// ---------------------------------------------------------------------------
// Login / logout side effects
// ---------------------------------------------------------------------------

describe('login & logout', () => {
  it('login stores the returned token', async () => {
    mockFetchOnce({
      body: { token: 'new-jwt', tokenType: 'Bearer', expiresAt: 'soon' },
    });
    const result = await api.login('a@b.c', 'pw');
    expect(result.token).toBe('new-jwt');
    expect(getToken()).toBe('new-jwt');
  });

  it('logout clears the token even when the server call fails', async () => {
    setToken('jwt-x');
    mockFetchOnce({ status: 500, body: { error: { message: 'boom' } } });
    await api.logout();
    expect(getToken()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Error envelope unwrapping
// ---------------------------------------------------------------------------

describe('error handling', () => {
  it('unwraps the API error envelope into ApiError', async () => {
    mockFetchOnce({
      status: 403,
      body: {
        error: {
          code: 'forbidden',
          message: 'scope denied',
          requestId: 'req-9',
          details: { scope: 'vault:use' },
        },
      },
    });

    await expect(api.listAgents()).rejects.toMatchObject({
      name: 'ApiError',
      status: 403,
      code: 'forbidden',
      message: 'scope denied',
      requestId: 'req-9',
    });
  });

  it('falls back to a synthetic code when no envelope is present', async () => {
    mockFetchOnce({ status: 404, rawText: 'not found' });
    try {
      await api.listPassports();
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
      expect((err as ApiError).code).toBe('http_404');
    }
  });

  it('maps network failures to a network_error ApiError', async () => {
    const fn = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    vi.stubGlobal('fetch', fn);

    await expect(api.listPassports()).rejects.toMatchObject({
      name: 'ApiError',
      status: 0,
      code: 'network_error',
    });
  });

  it('returns undefined for 204 No Content', async () => {
    mockFetchOnce({ status: 204 });
    // logout hits 204-style empty responses; ensure no parse error.
    setToken('t');
    await expect(api.logout()).resolves.toBeUndefined();
    expect(getToken()).toBeNull();
  });
});
