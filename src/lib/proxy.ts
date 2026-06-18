import http from 'node:http';
import https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import type { LookupAddress, LookupOptions } from 'node:dns';
import { env } from '../env.js';

// Sentinel on the lookup error so a blocked private/metadata resolution maps to
// forbidden_target (not a generic connection failure).
const BLOCKED_CODE = 'EAGENTAUTHBLOCKED';

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
 *   - Private/loopback/link-local/cloud-metadata hosts are refused unless
 *     PROXY_ALLOW_PRIVATE — both as a literal (incl. bracketed IPv6 and
 *     IPv4-mapped IPv6) AND after DNS resolution, so a public name that resolves
 *     to a private address is also rejected (SSRF / cloud-metadata guard).
 *   - The raw secret (and its base64 form) is redacted, best-effort and
 *     case-insensitively, from BOTH the returned body and the response headers,
 *     so a downstream that reflects the credential can't hand it back.
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

/**
 * Reduce a URL `host` (the value `new URL().host` returns, or a bare `host:port`)
 * to a clean lowercase hostname for the SSRF checks: strips IPv6 brackets, the
 * port, and a single trailing FQDN dot. A naive `host.split(':')[0]` mangles a
 * bracketed IPv6 literal to `"["` and bypasses every check — this does not.
 */
function hostnameOf(host: string): string {
  let h = host.trim();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    if (end >= 0) return h.slice(1, end).toLowerCase(); // IPv6 literal — already canonical
  }
  const colon = h.indexOf(':');
  if (colon >= 0) h = h.slice(0, colon); // strip :port (IPv4/hostname only)
  h = h.replace(/\.$/, '').toLowerCase(); // strip a single trailing dot
  // Canonicalize encoded IPv4 forms (decimal 2130706433, hex 0x7f000001, octal
  // 0177.0.0.1, short 127.1) the SAME way the URL parser will before connecting,
  // so the SSRF check sees the real dotted-quad — otherwise a bare encoded-IP
  // target slips past isPrivateHost and reaches loopback/metadata.
  if (h.length > 0 && !h.includes(':')) {
    try {
      const canon = new URL(`https://${h}`).hostname;
      if (canon) h = canon.toLowerCase();
    } catch {
      /* keep h as-is */
    }
  }
  return h;
}

/** If `h` is an IPv4-mapped IPv6 literal, return the embedded dotted IPv4. */
function unmapIpv4(h: string): string {
  if (!h.startsWith('::ffff:')) return h;
  const mapped = h.slice('::ffff:'.length);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(mapped)) return mapped; // ::ffff:127.0.0.1
  const parts = mapped.split(':'); // ::ffff:7f00:1 (hex word form)
  const [w0, w1] = parts;
  if (parts.length === 2 && w0 && w1 && /^[0-9a-f]{1,4}$/.test(w0) && /^[0-9a-f]{1,4}$/.test(w1)) {
    const hi = parseInt(w0, 16);
    const lo = parseInt(w1, 16);
    return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return h;
}

function isLoopbackHost(host: string): boolean {
  const h = unmapIpv4(host.toLowerCase());
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true;
  const m = h.match(/^(\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
  return m ? Number(m[1]) === 127 : false;
}

function isPrivateHost(host: string): boolean {
  const h = unmapIpv4(host.toLowerCase());
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
  // IPv6 unspecified, unique-local (fc00::/7) and link-local (fe80::/10). Gate on
  // h actually being an IPv6 literal so ordinary DNS names whose first label
  // starts with fc/fd/fe80 (e.g. fcm.googleapis.com) are NOT misclassified — a
  // name that truly resolves to a private IPv6 is still caught by resolvesToPrivate.
  if (
    isIP(h) === 6 &&
    (h === '::' || h.startsWith('fd') || h.startsWith('fc') || h.startsWith('fe80'))
  )
    return true;
  return false;
}

/**
 * Resolve a hostname and report whether ANY resolved address is private. Closes
 * the public-name-that-points-at-a-private-IP vector (e.g. a DNS record for
 * 169.254.169.254). IP literals are already covered by the string check, so they
 * skip resolution. A resolution failure returns false — the subsequent fetch
 * then fails as `upstream_unreachable`, never a default-allow to a real host.
 *
 * This is the pre-charge gate (so a private target is rejected before a use is
 * billed). The actual connection is additionally pinned to validated addresses
 * via makePinnedLookup, so a DNS name that rebinds between this check and the
 * connect cannot reach a private address either — the socket only dials IPs that
 * passed validation at connect time.
 */
async function resolvesToPrivate(hostname: string): Promise<boolean> {
  if (isIP(hostname)) return false; // literal — already string-checked
  try {
    const addrs = await dnsLookup(hostname, { all: true });
    return addrs.some((a) => isPrivateHost(a.address));
  } catch {
    return false;
  }
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

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The on-the-wire forms a downstream might reflect: the raw secret and its base64
 * encoding (basic-auth / token payloads). Redaction is exact + case-insensitive;
 * it cannot catch every transformation (gzip, arbitrary chunking) and is a
 * defense-in-depth layer behind the primary invariant that the secret is only
 * ever injected server-side, never sent to the agent.
 */
function secretVariants(secret: string): string[] {
  if (secret.length === 0) return [];
  const out = new Set<string>([secret]);
  try {
    out.add(Buffer.from(secret).toString('base64'));
    out.add(Buffer.from(secret).toString('base64url'));
  } catch {
    /* ignore */
  }
  // Encoded forms a downstream might reflect: query-mode injection puts the
  // secret through url.searchParams, so cover the EXACT application/x-www-form-
  // urlencoded bytes it emits (space->'+', and ! ' ( ) ~ -> %21 %27 %28 %29 %7E,
  // which encodeURIComponent does NOT encode) by deriving the variant the same
  // way the request does; also cover the plain percent-encoded form (e.g. a
  // Location header echoing the URL with %20).
  for (const v of [...out]) {
    const enc = encodeURIComponent(v);
    if (enc !== v) out.add(enc);
    const wire = new URLSearchParams([['k', v]]).toString().slice(2);
    if (wire !== v) out.add(wire);
  }
  return [...out].filter((v) => v.length > 0);
}

function redactAll(text: string, variants: string[]): string {
  let out = text;
  for (const v of variants) {
    out = out.replace(new RegExp(escapeRegExp(v), 'gi'), '[redacted]');
  }
  return out;
}

/**
 * Read a Node response stream into memory bounded by the byte cap. We over-read
 * by the longest secret variant so a secret straddling the cap boundary is still
 * fully present for redaction (which happens BEFORE the final truncate), then
 * enforce the byte cap on the redacted text.
 */
function readCappedBytes(res: http.IncomingMessage, cap: number): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    };
    res.on('data', (c: Buffer) => {
      if (total >= cap) return;
      let chunk = c;
      if (total + chunk.byteLength > cap) {
        chunk = chunk.subarray(0, cap - total);
        res.destroy();
      }
      chunks.push(chunk);
      total += chunk.byteLength;
      if (total >= cap) finish();
    });
    res.on('end', finish);
    res.on('close', finish);
    res.on('error', finish);
  });
}

/**
 * A DNS lookup that resolves the name, rejects it if ANY resolved address is
 * private/metadata (unless allowed), and returns ONLY the validated addresses —
 * so the socket connects to exactly what we checked. Using the same resolution
 * for validation and connection closes the DNS-rebinding TOCTOU that a separate
 * pre-check + fetch (which re-resolves) would leave open.
 */
function makePinnedLookup(allowPrivate: boolean): LookupFunction {
  const fn = (
    hostname: string,
    options: LookupOptions,
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | LookupAddress[],
      family?: number,
    ) => void,
  ): void => {
    dnsLookup(hostname, { all: true })
      .then((addrs) => {
        const usable = addrs.filter((a) => allowPrivate || !isPrivateHost(a.address));
        if (usable.length === 0) {
          const err = Object.assign(
            new Error('target resolves to a private/metadata address'),
            { code: BLOCKED_CODE },
          ) as NodeJS.ErrnoException;
          callback(err, '', 0);
          return;
        }
        if (options && options.all) {
          callback(
            null,
            usable.map((a) => ({ address: a.address, family: a.family })),
          );
        } else {
          callback(null, usable[0]!.address, usable[0]!.family);
        }
      })
      .catch((err) => callback(err as NodeJS.ErrnoException, '', 0));
  };
  return fn as unknown as LookupFunction;
}

type ProxyFailure = Extract<ProxyOutcome, { ok: false }>;

/**
 * Validate the target + path guards (path shape, private/loopback, plaintext
 * http, DNS-resolves-to-private) WITHOUT making the downstream call or touching
 * the secret. Returns a failure outcome, or null if the request may proceed.
 * Exposed so the route can run these guards BEFORE charging a use / spending an
 * approval, so a proxy rejected by the pre-charge checks never burns a maxUses
 * slot. (The connect-time pinned-lookup block for a DNS rebind is a separate,
 * rare backstop that can fire after the charge.)
 */
export async function precheckProxyTarget(target: string, path: string): Promise<ProxyFailure | null> {
  if (!path.startsWith('/'))
    return { ok: false, reason: 'bad_request', message: 'path must start with /' };

  const { scheme: targetScheme, host } = parseTarget(target);
  const bareHost = hostnameOf(host);

  // Guard order: string checks (no network) first, DNS resolution last.
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

  if (!env.PROXY_ALLOW_PRIVATE && (await resolvesToPrivate(bareHost))) {
    return {
      ok: false,
      reason: 'forbidden_target',
      message: 'target host resolves to a private/metadata address (set PROXY_ALLOW_PRIVATE to allow)',
    };
  }

  return null;
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
  const pre = await precheckProxyTarget(args.target, path);
  if (pre) return pre;

  const { scheme: targetScheme, host, basePath } = parseTarget(args.target);
  const scheme = targetScheme ?? 'https';

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

  // Redact the secret (and base64 / url-encoded forms) from EVERYTHING the agent
  // sees — body and response headers — before applying the byte cap.
  const variants = secretVariants(secret);
  const maxVariant = variants.reduce((m, v) => Math.max(m, Buffer.byteLength(v)), 0);
  const cap = env.PROXY_MAX_RESPONSE_BYTES;

  const lib = scheme === 'https' ? https : http;
  const lookup = makePinnedLookup(env.PROXY_ALLOW_PRIVATE);

  return await new Promise<ProxyOutcome>((resolve) => {
    let settled = false;
    let timedOut = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (o: ProxyOutcome) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(o);
    };

    // request() throws SYNCHRONOUSLY on a malformed header (the schema rejects
    // these first, so this is belt-and-suspenders) — keep the contract: resolve a
    // structured ProxyOutcome, never reject the promise.
    try {
      const req = lib.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port ? Number(url.port) : scheme === 'https' ? 443 : 80,
          path: `${url.pathname}${url.search}`,
          method,
          headers,
          lookup, // pin to validated IPs — no redirect is ever followed by node here
          servername: scheme === 'https' ? url.hostname : undefined, // correct TLS SNI
        },
        (res) => {
          readCappedBytes(res, cap + maxVariant + 8).then((raw) => {
            let body = redactAll(raw.toString('utf8'), variants);
            if (Buffer.byteLength(body) > cap)
              body = Buffer.from(body, 'utf8').subarray(0, cap).toString('utf8');
            const outHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v == null) continue;
              // Redact the secret from BOTH the header name and value — a reflecting
              // downstream could echo input into either.
              outHeaders[redactAll(k, variants)] = redactAll(
                Array.isArray(v) ? v.join(', ') : String(v),
                variants,
              );
            }
            finish({
              ok: true,
              response: { status: res.statusCode ?? 0, headers: outHeaders, body },
            });
          });
        },
      );

      timer = setTimeout(() => {
        timedOut = true;
        req.destroy();
      }, env.PROXY_TIMEOUT_MS);

      req.on('error', (err: NodeJS.ErrnoException) => {
        if (timedOut)
          return finish({ ok: false, reason: 'timeout', message: 'downstream request timed out' });
        if (err?.code === BLOCKED_CODE)
          return finish({
            ok: false,
            reason: 'forbidden_target',
            message:
              'target host resolves to a private/metadata address (set PROXY_ALLOW_PRIVATE to allow)',
          });
        finish({
          ok: false,
          reason: 'upstream_unreachable',
          message: 'failed to reach the downstream target',
        });
      });

      if (hasBody) req.write(args.request.body);
      req.end();
    } catch {
      finish({ ok: false, reason: 'bad_request', message: 'invalid request header' });
    }
  });
}
