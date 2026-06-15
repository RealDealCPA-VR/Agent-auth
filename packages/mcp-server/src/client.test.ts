import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AgentAuthClient,
  AgentAuthClientError,
  ApprovalPendingError,
  type CredentialsPage,
} from './client.js';

const BASE = 'http://localhost:8080';
const KEY = 'aa_11111111-1111-4111-8111-111111111111.supersecret';
const UUID = '22222222-2222-4222-8222-222222222222';

/** Build a fetch-like Response for a given status + JSON body. */
function jsonResponse(status: number, body: unknown): Response {
  const text = body === undefined ? '' : JSON.stringify(body);
  return new Response(text, {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** A typed mock of global fetch. */
function stubFetch(impl: (url: string, init?: RequestInit) => Promise<Response>) {
  const mock = vi.fn(impl as unknown as typeof fetch);
  vi.stubGlobal('fetch', mock);
  return mock;
}

function makeClient() {
  return new AgentAuthClient({ baseUrl: BASE, apiKey: KEY });
}

const samplePage: CredentialsPage = {
  items: [
    {
      id: UUID,
      target: 'github.com',
      label: 'GH token',
      type: 'api_key',
      metadata: {},
      expiresAt: null,
    },
  ],
  pagination: { limit: 200, offset: 0, total: 1, returned: 1 },
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('AgentAuthClient.listCredentials', () => {
  it('GETs the vault listing with the bearer key and forwards pagination', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(200, samplePage));
    const client = makeClient();

    const page = await client.listCredentials({ limit: 50, offset: 10 });

    expect(page).toEqual(samplePage);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    const parsed = new URL(url as string);
    expect(parsed.origin + parsed.pathname).toBe(`${BASE}/v1/vault/credentials`);
    expect(parsed.searchParams.get('limit')).toBe('50');
    expect(parsed.searchParams.get('offset')).toBe('10');
    expect((init as RequestInit).method).toBe('GET');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${KEY}`);
  });
});

describe('AgentAuthClient.useCredential by id (UUID)', () => {
  it('POSTs directly to /use without listing first, and returns the secret', async () => {
    const used = {
      id: UUID,
      target: 'github.com',
      label: 'GH token',
      type: 'api_key' as const,
      metadata: {},
      expiresAt: null,
      secret: 'ghp_live_secret',
    };
    const fetchMock = stubFetch(async () => jsonResponse(200, used));
    const client = makeClient();

    const result = await client.useCredential(UUID);

    expect(result.secret).toBe('ghp_live_secret');
    expect(fetchMock).toHaveBeenCalledTimes(1); // no listing round-trip
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${BASE}/v1/vault/credentials/${UUID}/use`);
    expect((init as RequestInit).method).toBe('POST');
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${KEY}`);
  });
});

describe('AgentAuthClient.useCredential by target (non-UUID)', () => {
  it('lists, matches items[].target, then POSTs that id /use', async () => {
    const used = {
      id: UUID,
      target: 'github.com',
      label: 'GH token',
      type: 'api_key' as const,
      metadata: {},
      expiresAt: null,
      secret: 'ghp_resolved_secret',
    };
    const calls: string[] = [];
    const fetchMock = stubFetch(async (url, init) => {
      calls.push(`${(init as RequestInit)?.method ?? 'GET'} ${url}`);
      if ((url as string).includes('/use')) return jsonResponse(200, used);
      return jsonResponse(200, samplePage); // the listing
    });
    const client = makeClient();

    const result = await client.useCredential('github.com');

    expect(result.secret).toBe('ghp_resolved_secret');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    // First a GET listing at page size 200, then the POST /use for the matched id.
    expect(calls[0]).toContain('GET');
    expect(calls[0]).toContain('/v1/vault/credentials?');
    expect(new URL(calls[0]!.split(' ')[1]!).searchParams.get('limit')).toBe('200');
    expect(calls[1]).toBe(`POST ${BASE}/v1/vault/credentials/${UUID}/use`);
  });

  it('throws a 404 AgentAuthClientError when no item matches the target', async () => {
    const emptyPage: CredentialsPage = {
      items: [],
      pagination: { limit: 200, offset: 0, total: 0, returned: 0 },
    };
    stubFetch(async () => jsonResponse(200, emptyPage));
    const client = makeClient();

    await expect(client.useCredential('nope.example.com')).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    });
  });
});

describe('AgentAuthClient.proxy by id (UUID)', () => {
  it('POSTs the proxy request directly without listing, returns the downstream response', async () => {
    const downstream = {
      status: 201,
      headers: { 'content-type': 'application/json' },
      body: '{"ok":true}',
    };
    const fetchMock = stubFetch(async () => jsonResponse(200, downstream));
    const client = makeClient();

    const result = await client.proxy(UUID, {
      method: 'POST',
      path: '/repos',
      query: { page: '2' },
      headers: { 'x-test': '1' },
      body: '{"name":"x"}',
    });

    expect(result).toEqual(downstream);
    expect(fetchMock).toHaveBeenCalledTimes(1); // no listing round-trip
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${BASE}/v1/vault/credentials/${UUID}/proxy`);
    const typedInit = init as RequestInit;
    expect(typedInit.method).toBe('POST');
    const headers = typedInit.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${KEY}`);
    expect(headers['content-type']).toBe('application/json');
    expect(JSON.parse(typedInit.body as string)).toEqual({
      method: 'POST',
      path: '/repos',
      query: { page: '2' },
      headers: { 'x-test': '1' },
      body: '{"name":"x"}',
    });
  });

  it('omits unset request fields from the JSON body (defaults applied server-side)', async () => {
    const downstream = { status: 200, headers: {}, body: '' };
    const fetchMock = stubFetch(async () => jsonResponse(200, downstream));
    const client = makeClient();

    await client.proxy(UUID);

    const [, init] = fetchMock.mock.calls[0]!;
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({});
  });
});

describe('AgentAuthClient.proxy by target (non-UUID)', () => {
  it('lists, matches items[].target, then POSTs that id /proxy', async () => {
    const downstream = { status: 200, headers: {}, body: 'pong' };
    const calls: string[] = [];
    const fetchMock = stubFetch(async (url, init) => {
      calls.push(`${(init as RequestInit)?.method ?? 'GET'} ${url}`);
      if ((url as string).includes('/proxy')) return jsonResponse(200, downstream);
      return jsonResponse(200, samplePage); // the listing
    });
    const client = makeClient();

    const result = await client.proxy('github.com', { path: '/ping' });

    expect(result).toEqual(downstream);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(calls[0]).toContain('GET');
    expect(calls[0]).toContain('/v1/vault/credentials?');
    expect(calls[1]).toBe(`POST ${BASE}/v1/vault/credentials/${UUID}/proxy`);
  });

  it('throws a 404 AgentAuthClientError when no item matches the target', async () => {
    const emptyPage: CredentialsPage = {
      items: [],
      pagination: { limit: 200, offset: 0, total: 0, returned: 0 },
    };
    stubFetch(async () => jsonResponse(200, emptyPage));
    const client = makeClient();

    await expect(client.proxy('nope.example.com')).rejects.toMatchObject({
      status: 404,
      code: 'not_found',
    });
  });
});

describe('AgentAuthClient.proxy error mapping', () => {
  it('maps a 403 forbidden_target envelope to a typed AgentAuthClientError', async () => {
    stubFetch(async () =>
      jsonResponse(403, {
        error: { code: 'forbidden_target', message: 'target not scoped', requestId: 'req-9' },
      }),
    );
    const client = makeClient();

    const err = (await client.proxy(UUID).catch((e: unknown) => e)) as AgentAuthClientError;
    expect(err).toBeInstanceOf(AgentAuthClientError);
    expect(err.status).toBe(403);
    expect(err.code).toBe('forbidden_target');
    expect(err.message).toBe('target not scoped');
    expect(err.requestId).toBe('req-9');
  });

  it('surfaces a 202 approval-pending proxy response as ApprovalPendingError', async () => {
    stubFetch(async () => jsonResponse(202, { status: 'pending', requestId: 'appr-proxy' }));
    const client = makeClient();

    const err = (await client.proxy(UUID).catch((e: unknown) => e)) as ApprovalPendingError;
    expect(err).toBeInstanceOf(ApprovalPendingError);
    expect(err.status).toBe(202);
    expect(err.code).toBe('approval_pending');
    expect(err.requestId).toBe('appr-proxy');
  });

  it('maps a 504 upstream timeout to a typed error', async () => {
    stubFetch(async () =>
      jsonResponse(504, { error: { code: 'timeout', message: 'upstream timed out' } }),
    );
    const client = makeClient();

    const err = (await client.proxy(UUID).catch((e: unknown) => e)) as AgentAuthClientError;
    expect(err.status).toBe(504);
    expect(err.code).toBe('timeout');
  });
});

describe('error mapping', () => {
  it('maps a 403 envelope to a typed AgentAuthClientError with code+message+requestId', async () => {
    stubFetch(async () =>
      jsonResponse(403, {
        error: { code: 'forbidden', message: 'target not allowed', requestId: 'req-123' },
      }),
    );
    const client = makeClient();

    const err = await client.useCredential(UUID).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AgentAuthClientError);
    const typed = err as AgentAuthClientError;
    expect(typed.status).toBe(403);
    expect(typed.code).toBe('forbidden');
    expect(typed.message).toBe('target not allowed');
    expect(typed.requestId).toBe('req-123');
  });

  it('falls back to default code/message when the body has no envelope', async () => {
    stubFetch(async () => jsonResponse(503, undefined));
    const client = makeClient();

    const err = (await client.listCredentials().catch((e: unknown) => e)) as AgentAuthClientError;
    expect(err).toBeInstanceOf(AgentAuthClientError);
    expect(err.status).toBe(503);
    expect(err.code).toBe('store_unavailable');
  });

  it('surfaces a 202 approval-pending response as ApprovalPendingError (not a result)', async () => {
    stubFetch(async () => jsonResponse(202, { status: 'pending', requestId: 'appr-9' }));
    const client = makeClient();

    const err = await client.useCredential(UUID).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApprovalPendingError);
    const typed = err as ApprovalPendingError;
    expect(typed.status).toBe(202);
    expect(typed.code).toBe('approval_pending');
    expect(typed.requestId).toBe('appr-9');
  });

  it('maps a network failure (rejected fetch) to status 0 network_error', async () => {
    stubFetch(async () => {
      throw new TypeError('fetch failed');
    });
    const client = makeClient();

    const err = (await client.listCredentials().catch((e: unknown) => e)) as AgentAuthClientError;
    expect(err).toBeInstanceOf(AgentAuthClientError);
    expect(err.status).toBe(0);
    expect(err.code).toBe('network_error');
  });
});
