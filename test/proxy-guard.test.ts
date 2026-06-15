import { describe, it, expect } from 'vitest';
import { proxyRequest } from '../src/lib/proxy.js';

// Default env (PROXY_ALLOW_PRIVATE=false, PROXY_ALLOW_HTTP=false). These cases
// all return BEFORE any network call, so no downstream is contacted.
const base = {
  type: 'api_key',
  injection: null,
  secret: 'x',
  request: { method: 'GET', path: '/' },
};

describe('proxy guards', () => {
  it('blocks private / loopback / link-local targets (SSRF guard)', async () => {
    const hosts = [
      '169.254.169.254', // cloud metadata
      '127.0.0.1',
      '10.0.0.5',
      '192.168.1.1',
      '172.16.0.1',
      'localhost',
      'metadata.google.internal',
    ];
    for (const target of hosts) {
      const r = await proxyRequest({ ...base, target });
      expect(r.ok, target).toBe(false);
      if (!r.ok) expect(r.reason).toBe('forbidden_target');
    }
  });

  it('refuses plaintext http to a non-loopback host', async () => {
    const r = await proxyRequest({ ...base, target: 'http://example.com' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('forbidden_target');
  });

  it('rejects a path that does not start with /', async () => {
    const r = await proxyRequest({
      ...base,
      target: 'example.com',
      request: { method: 'GET', path: 'oops' },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('bad_request');
  });
});
