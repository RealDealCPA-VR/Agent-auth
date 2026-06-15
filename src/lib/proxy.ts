import { env } from '../env.js';

/**
 * Proxy mode: AgentAuth makes the downstream request server-side and injects the
 * credential, so the raw secret never reaches the agent. Security invariants:
 *   - The URL host is ALWAYS the credential's bound `target`. The agent supplies
 *     only method/path/query/body — never the host or scheme — so a credential
 *     can't be redirected to an attacker-controlled host.
 *   - AgentAuth controls the injected auth header/param; the agent cannot set or
 *     override it, nor Host/hop-by-hop headers.
 *   - Redirects are NOT followed (a 3xx is returned as-is) so the credential
 *     can't be leaked to a redirect target.
 *   - Plaintext http to a non-loopback host is refused unless PROXY_ALLOW_HTTP.
 *   - Private/loopback/link-local hosts are refused unless PROXY_ALLOW_PRIVATE
 *     (SSRF / cloud-metadata guard).
 *   - The raw secret is redacted from the returned body.
 */

export type Injection =
  | { mode: 'bearer' }
  | { mode: 'basic' }
  | { mode: 'cookie' }
  | { mode: 'header'; name: string; prefix?: string }
  | { mode: 'query'; name: string };

export interface ProxyRequest {
  method: string;
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type ProxyOutcome =
  | { ok: true; response: ProxyResponse }
  | {
      ok: false;
      reason: 'forbidden_target' | 'bad_request' | 'timeout' | 'upstream_unreachable';
      message: string;
    };

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
]);

function defaultInjection(type: string): Injection {
  return type === 'cookie' ? { mode: 'cookie' } : { mode: 'bearer' };
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true;
  const m = h.match(/^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  return m ? Number(m[1]) === 127 : false;
}

function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (isLoopbackHost(h)) return true;
  if (h === 'metadata.google.internal' || h === 'metadata') return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 10 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  }
  // Rough IPv6 private/link-local/loopback.
  if (h.startsWith('fd') || h.startsWith('fc') || h.startsWith('fe80') || h === '::1') return true;
  return false;
}

/** Split a stored target into scheme (if any), host, and base path. */
function parseTarget(target: string): { scheme: string | null; host: string; basePath: string } {
  if (/^https?:\/\//i.test(target)) {
    try {
      const u = new URL(target);
      return {
        scheme: u.protocol.replace(':', '').toLowerCase(),
        host: u.host,
        basePath: u.pathname.replace(/\/$/, ''),
      };
    } catch {
      return { scheme: null, host: target, basePath: '' };
    }
  }
  const slash = target.indexOf('/');
  if (slash >= 0) {
    return {
      scheme: null,
      host: target.slice(0, slash),
      basePath: target.slice(slash).replace(/\/$/, ''),
    };
  }
  return { scheme: null, host: target, basePath: '' };
}

export async function proxyRequest(args: {
  target: string;
  type: string;
  injection: Injection | null;
  secret: string;
  request: ProxyRequest;
}): Promise<ProxyOutcome> {
  const { secret } = args;
  const injection = args.injection ?? defaultInjection(args.type);

  const path = args.request.path || '/';
  if (!path.startsWith('/'))
    return { ok: false, reason: 'bad_request', message: 'path must start with /' };

  const { scheme: targetScheme, host, basePath } = parseTarget(args.target);
  const bareHost = host.split(':')[0] ?? host;

  if (!env.PROXY_ALLOW_PRIVATE && isPrivateHost(bareHost)) {
    return {
      ok: false,
      reason: 'forbidden_target',
      message: 'target host is private/loopback (set PROXY_ALLOW_PRIVATE to allow)',
    };
  }

  const scheme = targetScheme ?? 'https';
  if (scheme === 'http' && !isLoopbackHost(bareHost) && !env.PROXY_ALLOW_HTTP) {
    return {
      ok: false,
      reason: 'forbidden_target',
      message: 'refusing to send a credential over plaintext http to a non-loopback host',
    };
  }

  // Build the URL: host is pinned, agent controls path + query only.
  let url: URL;
  try {
    url = new URL(`${scheme}://${host}${basePath}${path}`);
  } catch {
    return { ok: false, reason: 'bad_request', message: 'invalid path' };
  }
  for (const [k, v] of Object.entries(args.request.query ?? {})) url.searchParams.set(k, v);

  // Headers: start from agent-supplied, drop anything we control or that's unsafe.
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(args.request.headers ?? {})) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || key === 'authorization' || key === 'cookie') continue;
    if (injection.mode === 'header' && key === injection.name.toLowerCase()) continue;
    headers[key] = v;
  }

  // Apply injection LAST so the agent can never override it.
  switch (injection.mode) {
    case 'bearer':
      headers['authorization'] = `Bearer ${secret}`;
      break;
    case 'basic':
      headers['authorization'] = `Basic ${Buffer.from(secret).toString('base64')}`;
      break;
    case 'cookie':
      headers['cookie'] = secret;
      break;
    case 'header':
      headers[injection.name.toLowerCase()] = `${injection.prefix ?? ''}${secret}`;
      break;
    case 'query':
      url.searchParams.set(injection.name, secret);
      break;
  }

  const method = (args.request.method || 'GET').toUpperCase();
  const hasBody = !['GET', 'HEAD'].includes(method) && args.request.body != null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), env.PROXY_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: hasBody ? args.request.body : undefined,
      redirect: 'manual', // never follow — don't leak the credential to a 3xx host
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if ((err as Error)?.name === 'AbortError') {
      return { ok: false, reason: 'timeout', message: 'downstream request timed out' };
    }
    return {
      ok: false,
      reason: 'upstream_unreachable',
      message: 'failed to reach the downstream target',
    };
  }
  clearTimeout(timer);

  // Read the body with a size cap; redact the raw secret defensively.
  let body = await res.text();
  if (body.length > env.PROXY_MAX_RESPONSE_BYTES)
    body = body.slice(0, env.PROXY_MAX_RESPONSE_BYTES);
  if (secret.length > 0) body = body.split(secret).join('[redacted]');

  const outHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    outHeaders[k] = v;
  });

  return { ok: true, response: { status: res.status, headers: outHeaders, body } };
}
