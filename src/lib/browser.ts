import { z } from 'zod';
import { targetHost } from '../auth/agent.js';

/**
 * Browser-login mode: AgentAuth turns a vault credential into a concrete set of
 * browser actions ("set these cookies", "fill this login form", "set this auth
 * header") so an agent that drives a real browser (Playwright/Puppeteer, computer
 * use, etc.) can authenticate to a web app WITHOUT having to handle the raw secret
 * in its own reasoning/tool layer.
 *
 * Trust model — read this before extending:
 *   - The returned {@link BrowserLoginPlan} CARRIES the secret (cookie value, auth
 *     header, or the password typed into a form). It is the SAME trust level as
 *     the `/use` endpoint: the caller receives secret material. The strong
 *     "secret never reaches the agent" guarantee is the PROXY path (HTTP only).
 *   - For the browser case, the meaningful boundary is enforced by the SDK helper,
 *     which applies the plan to a page object and confines the secret to the SDK
 *     process's memory — the plan (and its secret) is never returned up to the
 *     agent's LLM/tool result. See packages/sdk-ts (browser helper).
 *   - This module NEVER logs the secret; the route audits mode + target only.
 *
 * The non-secret SPEC lives in a credential's `metadata.browser` (deposited by the
 * human owner): selectors, login URL, cookie names, which field is the username.
 * It is non-secret on purpose so it can travel in listing metadata and be edited
 * in the admin UI. The SECRET is filled in here, server-side, at plan-build time.
 */

// --- The non-secret spec (stored in credential metadata.browser) ------------

const sameSite = z.enum(['Lax', 'Strict', 'None']);

/** A cookie to set, named in the spec; its value is resolved from the secret. */
const cookieSpec = z.object({
  name: z.string().min(1).max(256),
  domain: z.string().min(1).max(253).optional(),
  path: z.string().startsWith('/').max(1024).optional(),
  secure: z.boolean().optional(),
  httpOnly: z.boolean().optional(),
  sameSite: sameSite.optional(),
});

/** A single login-form field: filled from the secret, the username, or a literal. */
const formField = z.union([
  z.object({ selector: z.string().min(1).max(1024), valueFrom: z.enum(['secret', 'username']) }),
  z.object({ selector: z.string().min(1).max(1024), value: z.string().max(4096) }),
]);

const httpUrl = z
  .string()
  .max(2048)
  .refine((u) => /^https?:\/\//i.test(u), 'must be an http(s) URL');

// An HTTP header field-name token (RFC 7230) and a visible-ASCII value, mirroring
// the proxy route's deposit-time validation (src/routes/passports.ts): a header
// name/prefix that contains CR/LF/NUL/control chars must be rejected as a bad
// spec rather than smuggled verbatim into a returned plan (header-injection /
// request-splitting hygiene, consistent with proxy-mode injection).
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const HEADER_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;

export const browserSpecSchema = z.discriminatedUnion('mode', [
  z.object({
    mode: z.literal('cookie'),
    // When omitted, the secret is parsed as a `name=value; name2=value2` cookie
    // string (the natural shape of a captured session cookie).
    cookies: z.array(cookieSpec).max(50).optional(),
    url: httpUrl.optional(),
  }),
  z.object({
    mode: z.literal('header'),
    header: z.string().min(1).max(256).regex(HEADER_NAME_RE, 'invalid header name').optional(), // default Authorization
    prefix: z.string().max(64).regex(HEADER_VALUE_RE, 'invalid header prefix').optional(), // default 'Bearer '
    url: httpUrl.optional(),
  }),
  z.object({
    mode: z.literal('localStorage'),
    origin: httpUrl, // the origin whose localStorage to populate
    key: z.string().min(1).max(256),
    url: httpUrl.optional(),
  }),
  z.object({
    mode: z.literal('form'),
    url: httpUrl, // the login page to open
    fields: z.array(formField).min(1).max(20),
    submitSelector: z.string().min(1).max(1024).optional(),
    // Optional substring the post-login URL should contain — advisory, for the
    // SDK helper to verify success. Never affects plan building.
    successUrlIncludes: z.string().max(2048).optional(),
  }),
]);

export type BrowserSpec = z.infer<typeof browserSpecSchema>;

// --- The concrete, secret-bearing plan (returned to the caller) -------------

export interface PlanCookie {
  name: string;
  value: string;
  domain?: string;
  path: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
}

export type BrowserFormAction =
  | { type: 'goto'; url: string }
  | { type: 'fill'; selector: string; value: string }
  | { type: 'click'; selector: string };

export type BrowserLoginPlan =
  | { mode: 'cookie'; target: string; url: string; cookies: PlanCookie[] }
  | { mode: 'header'; target: string; url: string; headers: Record<string, string> }
  | { mode: 'localStorage'; target: string; origin: string; url: string; items: Record<string, string> }
  | {
      mode: 'form';
      target: string;
      url: string;
      actions: BrowserFormAction[];
      successUrlIncludes?: string;
    };

export type BuildPlanResult =
  | { ok: true; plan: BrowserLoginPlan }
  | {
      ok: false;
      reason: 'no_browser_spec' | 'bad_browser_spec' | 'missing_username' | 'forbidden_target';
      message: string;
    };

// A cookie value containing a control char (incl. CR/LF/NUL) or ';' is illegal —
// a browser truncates/drops it. A header value with CR/LF/NUL/control is a
// header-injection hazard. Validate the SECRET-derived values before emitting a
// plan so a malformed deposited secret yields a clean bad_browser_spec rather
// than a silently-broken plan (the value-side analogue of the proxy route's
// header hygiene, which the names/prefix checks above only cover structurally).
const ILLEGAL_COOKIE_VALUE_RE = /[\x00-\x1f\x7f;]/;

/** Default landing URL for cookie/header/localStorage application: https://<host>/. */
function defaultUrl(target: string): string {
  if (/^https?:\/\//i.test(target.trim())) {
    try {
      return new URL(target.trim()).toString();
    } catch {
      /* fall through to host form */
    }
  }
  return `https://${targetHost(target)}/`;
}

/**
 * Parse a cookie credential's secret into discrete cookies bound to the target
 * host. The bundle-vs-bare decision must NOT key on the mere presence of `=`:
 * many single-value secrets contain `=` (base64 padding like `abc123==`, JWTs).
 * So:
 *   - A `;`-separated string is a multi-cookie bundle (`name=value; name2=value2`).
 *   - Otherwise it is ONE cookie. It is split into `name=value` only when the
 *     part before the first `=` is a valid cookie-name token AND the value after
 *     it carries no further `=` (so a base64-padded / JWT token is kept whole as
 *     the value of a single `session` cookie instead of being mangled).
 */
function parseCookieSecret(secret: string, host: string): PlanCookie[] {
  const trimmed = secret.trim();
  if (!trimmed) return [];
  if (trimmed.includes(';')) {
    const out: PlanCookie[] = [];
    for (const part of trimmed.split(';')) {
      const seg = part.trim();
      if (!seg) continue;
      const eq = seg.indexOf('=');
      if (eq <= 0) continue;
      const name = seg.slice(0, eq).trim();
      const value = seg.slice(eq + 1).trim();
      if (name) out.push({ name, value, domain: host, path: '/' });
    }
    // A ';'-shaped secret with no valid name=value segment is malformed: return
    // nothing so the caller surfaces a clean bad_browser_spec rather than emitting
    // a cookie whose value still contains ';' (illegal — a browser would truncate it).
    return out;
  }
  const eq = trimmed.indexOf('=');
  if (eq > 0) {
    const name = trimmed.slice(0, eq);
    const value = trimmed.slice(eq + 1);
    if (HEADER_NAME_RE.test(name) && value.length > 0 && !value.includes('=')) {
      return [{ name, value, domain: host, path: '/' }];
    }
  }
  return [{ name: 'session', value: trimmed, domain: host, path: '/' }];
}

/**
 * True when `rawUrl`'s host equals the credential's bound target host or is a
 * subdomain of it. Used to keep a secret-bearing browser plan aimed only at the
 * credential's target — the browser analogue of the proxy route's host pinning.
 */
function hostMatches(rawUrl: string, host: string): boolean {
  try {
    const h = new URL(rawUrl).hostname.toLowerCase().replace(/\.$/, '');
    return h === host || h.endsWith('.' + host);
  } catch {
    return false;
  }
}

/**
 * Reject a spec whose owner-supplied url/origin points at a host other than the
 * credential's bound target (or a subdomain). Keeps the secret-bearing plan from
 * being aimed at an unrelated origin, matching the /proxy host-pin invariant.
 * Returns a failure or null. A spec that omits the url (default is derived from
 * the target) trivially passes.
 */
function specHostViolation(
  spec: BrowserSpec,
  host: string,
): Extract<BuildPlanResult, { ok: false }> | null {
  const urls: string[] = [];
  if (spec.mode === 'localStorage') {
    urls.push(spec.origin);
    if (spec.url) urls.push(spec.url);
  } else if (spec.mode === 'form') {
    urls.push(spec.url);
  } else if (spec.url) {
    urls.push(spec.url); // cookie / header
  }
  for (const raw of urls) {
    if (!hostMatches(raw, host)) {
      // Same authorization class as the proxy route's off-host/SSRF rejection —
      // surface it as forbidden_target (mapped to 403) for cross-route consistency.
      return {
        ok: false,
        reason: 'forbidden_target',
        message: `browser-login url/origin host must match the credential target (${host})`,
      };
    }
  }
  return null;
}

/**
 * Resolve the effective spec for a credential WITHOUT its secret: the stored
 * metadata.browser if present and valid, else a type-derived default. Returns a
 * typed failure if no default exists or the stored spec is malformed.
 */
function resolveSpec(
  type: string,
  spec: unknown,
): { ok: true; spec: BrowserSpec } | Extract<BuildPlanResult, { ok: false }> {
  if (spec == null) {
    if (type === 'cookie') return { ok: true, spec: { mode: 'cookie' } };
    if (type === 'api_key' || type === 'oauth_token') return { ok: true, spec: { mode: 'header' } };
    return {
      ok: false,
      reason: 'no_browser_spec',
      message:
        'this credential has no browser-login spec; set metadata.browser (e.g. a form spec) to enable browser login',
    };
  }
  const parsed = browserSpecSchema.safeParse(spec);
  if (!parsed.success) {
    return { ok: false, reason: 'bad_browser_spec', message: 'metadata.browser is not a valid browser-login spec' };
  }
  return { ok: true, spec: parsed.data };
}

/**
 * Validate that a browser plan CAN be built for this credential without unsealing
 * the secret — so the route runs this BEFORE charging a use (charge-after-validate,
 * mirroring the proxy precheck). Catches a missing/invalid spec and a form that
 * needs a username the credential doesn't carry. Returns the failure, or null if
 * a plan will build. The secret-dependent build (buildBrowserPlan) only runs after
 * a use is charged; it can still fail for an empty-secret cookie, which the route
 * compensates by refunding.
 */
export function precheckBrowserSpec(
  type: string,
  target: string,
  metadata: unknown,
  spec: unknown,
): Extract<BuildPlanResult, { ok: false }> | null {
  const resolved = resolveSpec(type, spec);
  if (!resolved.ok) return resolved;
  const hostViolation = specHostViolation(resolved.spec, targetHost(target));
  if (hostViolation) return hostViolation;
  if (resolved.spec.mode === 'form') {
    const meta = (metadata ?? {}) as Record<string, unknown>;
    const needsUsername = resolved.spec.fields.some(
      (f) => 'valueFrom' in f && f.valueFrom === 'username',
    );
    if (needsUsername && typeof meta.username !== 'string') {
      return {
        ok: false,
        reason: 'missing_username',
        message: 'browser form references the username but metadata.username is not set',
      };
    }
  }
  return null;
}

/**
 * Build a concrete browser login plan from a credential's stored (non-secret)
 * browser spec and its unsealed secret. When no spec is configured, a sensible
 * default is derived from the credential type:
 *   - cookie  -> cookie plan (the secret parsed as a cookie string)
 *   - api_key / oauth_token -> header plan (Authorization: Bearer <secret>)
 *   - password -> requires an explicit form spec (no safe default).
 *
 * Returns a typed failure (never throws) so the route maps it to a clean 4xx.
 */
export function buildBrowserPlan(args: {
  target: string;
  type: string;
  secret: string;
  metadata: unknown;
  spec: unknown;
}): BuildPlanResult {
  const host = targetHost(args.target);
  const meta = (args.metadata ?? {}) as Record<string, unknown>;
  const username = typeof meta.username === 'string' ? meta.username : undefined;

  const resolved = resolveSpec(args.type, args.spec);
  if (!resolved.ok) return resolved;
  const spec = resolved.spec;

  // Host-pin the secret-bearing plan to the credential's target (defense-in-depth;
  // also enforced pre-charge by precheckBrowserSpec on the route).
  const hostViolation = specHostViolation(spec, host);
  if (hostViolation) return hostViolation;

  switch (spec.mode) {
    case 'cookie': {
      const url = spec.url ?? defaultUrl(args.target);
      // Build a plan cookie from a named spec cookie + its resolved value, carrying
      // through only the explicitly-set attributes.
      const mkCookie = (c: z.infer<typeof cookieSpec>, value: string): PlanCookie => ({
        name: c.name,
        value,
        domain: c.domain ?? host,
        path: c.path ?? '/',
        ...(c.secure !== undefined ? { secure: c.secure } : {}),
        ...(c.httpOnly !== undefined ? { httpOnly: c.httpOnly } : {}),
        ...(c.sameSite !== undefined ? { sameSite: c.sameSite } : {}),
      });

      let cookies: PlanCookie[];
      if (spec.cookies && spec.cookies.length > 0) {
        // Resolve each named cookie's value DETERMINISTICALLY, WITHOUT inferring
        // bundle-vs-bare from the mere presence of `=` (which misroutes base64 /
        // JWT secrets), and never smear the whole secret into an unmatched name:
        //  - ONE named cookie: the entire secret is that cookie's value.
        //  - MULTIPLE named cookies: the secret must be a `;`-bundle and every
        //    named cookie must appear in it; an unmatched name is a bad spec.
        if (spec.cookies.length === 1) {
          cookies = [mkCookie(spec.cookies[0]!, args.secret)];
        } else {
          const bundle = new Map(parseCookieSecret(args.secret, host).map((c) => [c.name, c.value]));
          const mapped: PlanCookie[] = [];
          for (const c of spec.cookies) {
            const value = bundle.get(c.name);
            if (value === undefined) {
              return {
                ok: false,
                reason: 'bad_browser_spec',
                message: `cookie "${c.name}" is not present in the credential secret`,
              };
            }
            mapped.push(mkCookie(c, value));
          }
          cookies = mapped;
        }
      } else {
        cookies = parseCookieSecret(args.secret, host);
      }
      if (cookies.length === 0) {
        return { ok: false, reason: 'bad_browser_spec', message: 'no cookies could be derived from the secret' };
      }
      if (cookies.some((c) => ILLEGAL_COOKIE_VALUE_RE.test(c.value))) {
        return {
          ok: false,
          reason: 'bad_browser_spec',
          message: 'cookie value contains illegal characters (control chars or ";")',
        };
      }
      return { ok: true, plan: { mode: 'cookie', target: host, url, cookies } };
    }
    case 'header': {
      const url = spec.url ?? defaultUrl(args.target);
      const headerName = spec.header ?? 'Authorization';
      const prefix = spec.prefix ?? (headerName.toLowerCase() === 'authorization' ? 'Bearer ' : '');
      const headerValue = `${prefix}${args.secret}`;
      if (!HEADER_VALUE_RE.test(headerValue)) {
        return {
          ok: false,
          reason: 'bad_browser_spec',
          message: 'header value contains illegal characters (control chars / CR/LF)',
        };
      }
      return {
        ok: true,
        plan: { mode: 'header', target: host, url, headers: { [headerName]: headerValue } },
      };
    }
    case 'localStorage': {
      const url = spec.url ?? spec.origin;
      return {
        ok: true,
        plan: {
          mode: 'localStorage',
          target: host,
          origin: spec.origin,
          url,
          items: { [spec.key]: args.secret },
        },
      };
    }
    case 'form': {
      const actions: BrowserFormAction[] = [{ type: 'goto', url: spec.url }];
      for (const f of spec.fields) {
        let value: string;
        if ('value' in f) {
          value = f.value;
        } else if (f.valueFrom === 'secret') {
          value = args.secret;
        } else {
          if (username === undefined) {
            return {
              ok: false,
              reason: 'missing_username',
              message: 'browser form references the username but metadata.username is not set',
            };
          }
          value = username;
        }
        actions.push({ type: 'fill', selector: f.selector, value });
      }
      if (spec.submitSelector) actions.push({ type: 'click', selector: spec.submitSelector });
      return {
        ok: true,
        plan: {
          mode: 'form',
          target: host,
          url: spec.url,
          actions,
          ...(spec.successUrlIncludes !== undefined ? { successUrlIncludes: spec.successUrlIncludes } : {}),
        },
      };
    }
  }
}
