import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildBrowserPlan } from '../src/lib/browser.js';
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

/** Issue an agent and return a bound POST helper for the browser-login endpoint. */
async function setup(scopes: string[] = ['vault:read', 'vault:use', 'target:app.example.com']) {
  const { token } = await registerAndLogin(app);
  const passportId = await createPassport(app, token);
  const agent = await issueAgent(app, token, passportId, scopes, 'browser-bot');
  const key = agent.apiKey;
  const browserLogin = (id: string) =>
    app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${id}/browser-login`,
      headers: auth(key),
    });
  return { token, passportId, browserLogin };
}

describe('browser-login (plan building)', () => {
  it('builds a cookie plan from a cookie credential, splitting name=value pairs', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'sid=abc123; theme=dark',
    });

    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.mode).toBe('cookie');
    expect(plan.target).toBe('app.example.com');
    expect(plan.url).toBe('https://app.example.com/');
    expect(plan.cookies).toEqual([
      { name: 'sid', value: 'abc123', domain: 'app.example.com', path: '/' },
      { name: 'theme', value: 'dark', domain: 'app.example.com', path: '/' },
    ]);
  });

  it('maps named cookies to their matching bundle values — never smears the whole secret', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'sid=abc123; csrf=xyz; refresh=longlived',
      metadata: {
        browser: { mode: 'cookie', cookies: [{ name: 'sid' }, { name: 'csrf' }] },
      },
    });

    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.cookies).toEqual([
      { name: 'sid', value: 'abc123', domain: 'app.example.com', path: '/' },
      { name: 'csrf', value: 'xyz', domain: 'app.example.com', path: '/' },
    ]);
    // Critically: no cookie value contains the full bundle / the refresh token.
    for (const c of plan.cookies) {
      expect(c.value).not.toContain('refresh');
      expect(c.value).not.toContain(';');
    }
  });

  it('422 bad_browser_spec when a named cookie is absent from the secret bundle', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'sid=abc123; csrf=xyz',
      metadata: { browser: { mode: 'cookie', cookies: [{ name: 'sid' }, { name: 'nope' }] } },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(422);
    expect(res.json().error.code).toBe('bad_browser_spec');
  });

  it('fills a single named cookie from a bare-value secret', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'bareValue123',
      metadata: { browser: { mode: 'cookie', cookies: [{ name: 'session' }] } },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    expect(res.json().cookies).toEqual([
      { name: 'session', value: 'bareValue123', domain: 'app.example.com', path: '/' },
    ]);
  });

  it('422 when a bare-value secret is asked to fill multiple named cookies', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'bareValue123',
      metadata: { browser: { mode: 'cookie', cookies: [{ name: 'a' }, { name: 'b' }] } },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(422);
    expect(res.json().error.code).toBe('bad_browser_spec');
  });

  it('keeps a base64-padded (=) secret whole for a single named cookie (not split as a bundle)', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'YWJjMTIz==', // base64 padding contains '=' but is NOT a bundle
      metadata: { browser: { mode: 'cookie', cookies: [{ name: 'session' }] } },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    expect(res.json().cookies).toEqual([
      { name: 'session', value: 'YWJjMTIz==', domain: 'app.example.com', path: '/' },
    ]);
  });

  it('no-spec cookie default keeps a base64-padded secret whole as one session cookie', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'tok123==',
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    expect(res.json().cookies).toEqual([
      { name: 'session', value: 'tok123==', domain: 'app.example.com', path: '/' },
    ]);
  });

  it('rejects (400) at deposit a form spec whose url points at a non-target host (host pinning)', async () => {
    const { token, passportId } = await setup();
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: {
        target: 'app.example.com',
        label: 'login',
        type: 'password',
        secret: 's3cr3t',
        metadata: {
          username: 'alice',
          browser: {
            mode: 'form',
            url: 'https://evil.example.org/login',
            fields: [{ selector: '#pass', valueFrom: 'secret' }],
          },
        },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('allows a spec url on a subdomain of the credential target', async () => {
    const { token, passportId, browserLogin } = await setup(['vault:use', 'target:example.com']);
    const cred = await deposit(app, token, passportId, {
      target: 'example.com',
      label: 'jwt',
      type: 'api_key',
      secret: 'jwt-value',
      metadata: {
        browser: { mode: 'localStorage', origin: 'https://app.example.com', key: 'auth' },
      },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    expect(res.json().origin).toBe('https://app.example.com');
  });

  it('rejects (400) at deposit a header spec with a CRLF-injected header name', async () => {
    const { token, passportId } = await setup();
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: {
        target: 'app.example.com',
        label: 'key',
        type: 'api_key',
        secret: 'tok',
        metadata: { browser: { mode: 'header', header: 'X-Foo\r\nSet-Cookie: evil' } },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('defaults an api_key credential to a Bearer Authorization header plan', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'key',
      type: 'api_key',
      secret: 'tok_live_42',
    });

    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.mode).toBe('header');
    expect(plan.headers).toEqual({ Authorization: 'Bearer tok_live_42' });
  });

  it('builds a form plan with goto + username/secret fills + submit click', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'login',
      type: 'password',
      secret: 's3cr3t',
      metadata: {
        username: 'alice',
        browser: {
          mode: 'form',
          url: 'https://app.example.com/login',
          fields: [
            { selector: '#user', valueFrom: 'username' },
            { selector: '#pass', valueFrom: 'secret' },
          ],
          submitSelector: 'button[type=submit]',
          successUrlIncludes: '/dashboard',
        },
      },
    });

    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.mode).toBe('form');
    expect(plan.url).toBe('https://app.example.com/login');
    expect(plan.successUrlIncludes).toBe('/dashboard');
    expect(plan.actions).toEqual([
      { type: 'goto', url: 'https://app.example.com/login' },
      { type: 'fill', selector: '#user', value: 'alice' },
      { type: 'fill', selector: '#pass', value: 's3cr3t' },
      { type: 'click', selector: 'button[type=submit]' },
    ]);
  });

  it('builds a localStorage plan from an explicit spec', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'jwt',
      type: 'api_key',
      secret: 'jwt-value',
      metadata: {
        browser: { mode: 'localStorage', origin: 'https://app.example.com', key: 'auth_token' },
      },
    });

    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.mode).toBe('localStorage');
    expect(plan.origin).toBe('https://app.example.com');
    expect(plan.items).toEqual({ auth_token: 'jwt-value' });
  });

  it('422 no_browser_spec for a password credential with no spec — and does NOT charge a use', async () => {
    const { token, passportId, browserLogin } = await setup();
    // maxUses:1 — if the rejected call wrongly charged, a later valid call would 429.
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'bare-pw',
      type: 'password',
      secret: 'pw',
      maxUses: 1,
    });

    const first = await browserLogin(cred.id);
    expect(first.statusCode).toBe(422);
    expect(first.json().error.code).toBe('no_browser_spec');

    // The use was never charged, so a second rejection is still 422 (not 429).
    const second = await browserLogin(cred.id);
    expect(second.statusCode).toBe(422);
    expect(second.json().error.code).toBe('no_browser_spec');
  });

  it('rejects (400) at deposit a form spec referencing username with no username value', async () => {
    const { token, passportId } = await setup();
    const res = await app.inject({
      method: 'POST',
      url: `/v1/passports/${passportId}/credentials`,
      headers: auth(token),
      payload: {
        target: 'app.example.com',
        label: 'login',
        type: 'password',
        secret: 's3cr3t',
        metadata: {
          browser: {
            mode: 'form',
            url: 'https://app.example.com/login',
            fields: [{ selector: '#user', valueFrom: 'username' }],
          },
        },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('invalid_request');
  });

  it('charges exactly one use: a maxUses:1 form credential 429s on the second call', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'login',
      type: 'password',
      secret: 's3cr3t',
      maxUses: 1,
      metadata: {
        username: 'bob',
        browser: {
          mode: 'form',
          url: 'https://app.example.com/login',
          fields: [
            { selector: '#user', valueFrom: 'username' },
            { selector: '#pass', valueFrom: 'secret' },
          ],
        },
      },
    });

    const first = await browserLogin(cred.id);
    expect(first.statusCode).toBe(200);
    const second = await browserLogin(cred.id);
    expect(second.statusCode).toBe(429);
    expect(second.json().error.code).toBe('use_limit_reached');
  });

  it('403 when the agent lacks vault:use', async () => {
    const { token, passportId } = await setup();
    const agent = await issueAgent(
      app,
      token,
      passportId,
      ['vault:read', 'target:app.example.com'],
      'readonly',
    );
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'c',
      type: 'cookie',
      secret: 'sid=x',
    });
    const res = await app.inject({
      method: 'POST',
      url: `/v1/vault/credentials/${cred.id}/browser-login`,
      headers: auth(agent.apiKey),
    });
    expect(res.statusCode).toBe(403);
  });

  it('403 when the credential target is outside the agent target scope', async () => {
    const { token, passportId, browserLogin } = await setup(['vault:use', 'target:other.example.com']);
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'c',
      type: 'cookie',
      secret: 'sid=x',
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(403);
  });

  it('422 bad_browser_spec when a cookie secret contains illegal characters (CR/LF)', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'abc\r\ndef',
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(422);
    expect(res.json().error.code).toBe('bad_browser_spec');
  });

  it('records a dedicated credential.browser audit action on success', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'sid=abc',
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);

    const trail = await app.inject({ method: 'GET', url: '/v1/audit', headers: auth(token) });
    const actions = (trail.json().items as Array<{ action: string }>).map((i) => i.action);
    expect(actions).toContain('credential.browser');
  });

  it('echoes a configured metadata.browser.mfa block into the form plan', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'login',
      type: 'password',
      secret: 's3cr3t',
      metadata: {
        username: 'alice',
        browser: {
          mode: 'form',
          url: 'https://app.example.com/login',
          fields: [
            { selector: '#user', valueFrom: 'username' },
            { selector: '#pass', valueFrom: 'secret' },
          ],
          submitSelector: '#go',
          successUrlIncludes: '/dashboard',
          mfa: { kind: 'totp', detectBy: 'auto', channelHint: 'authenticator app', inputSelector: '#otp' },
        },
      },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    const plan = res.json();
    expect(plan.mode).toBe('form');
    expect(plan.mfa).toEqual({
      kind: 'totp',
      detectBy: 'auto',
      channelHint: 'authenticator app',
      inputSelector: '#otp',
    });
  });

  it('echoes allowedDomains into a cookie plan (allowlist available to all modes)', async () => {
    const { token, passportId, browserLogin } = await setup();
    const cred = await deposit(app, token, passportId, {
      target: 'app.example.com',
      label: 'session',
      type: 'cookie',
      secret: 'sid=abc',
      metadata: { browser: { mode: 'cookie', allowedDomains: ['app.example.com'] } },
    });
    const res = await browserLogin(cred.id);
    expect(res.statusCode).toBe(200);
    expect(res.json().allowedDomains).toEqual(['app.example.com']);
  });

  it('404 for an unknown credential id', async () => {
    const { browserLogin } = await setup();
    const res = await browserLogin('00000000-0000-4000-8000-000000000000');
    expect(res.statusCode).toBe(404);
  });

  it('buildBrowserPlan flags an off-host spec url as forbidden_target (maps to 403)', () => {
    const r = buildBrowserPlan({
      target: 'app.example.com',
      type: 'password',
      secret: 'x',
      metadata: { username: 'a' },
      spec: {
        mode: 'form',
        url: 'https://evil.example.org/login',
        fields: [{ selector: '#u', valueFrom: 'username' }],
      },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('forbidden_target');
  });
});
