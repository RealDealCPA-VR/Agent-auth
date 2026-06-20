# @agentauth/sdk

The official **TypeScript SDK** for [AgentAuth](../../README.md) — the agent
credential vault. It ships two clients:

- **`AgentAuthClient`** — for your **agent** runtime. Holds an agent API key
  (`aa_<uuid>.<secret>`) and turns "I need to log into github.com" into one line:
  `await aa.useCredential('github.com')`.
- **`HumanClient`** — for your **admin / operator** tooling. Holds a session JWT
  and manages passports, credentials, agents, and the audit log.

Zero runtime dependencies — it uses the global `fetch` (Node 20+, Deno, Bun, and
modern browsers). Every non-2xx response is thrown as a typed `AgentAuthError`.
The SDK never logs secrets; they flow through return values only.

## Install

```bash
pnpm add @agentauth/sdk
# or: npm i @agentauth/sdk / yarn add @agentauth/sdk
```

## Agent usage

```ts
import { AgentAuthClient, AgentAuthError } from '@agentauth/sdk';

const aa = new AgentAuthClient({
  baseUrl: 'https://vault.example.com',
  apiKey: process.env.AGENTAUTH_KEY!, // aa_<uuid>.<secret>, shown once at mint time
});

// Discover what this agent is scoped to use (no secrets here):
const { items } = await aa.listCredentials();

try {
  // Resolve by target (any non-UUID string) — the SDK finds the id for you:
  const cred = await aa.useCredential('github.com');
  // ...or pass a credential id (a UUID) directly to skip the lookup:
  // const cred = await aa.useCredential('22222222-2222-4222-8222-...');

  authenticateToGithub(cred.secret); // use immediately; never log or persist it
} catch (err) {
  if (err instanceof AgentAuthError) {
    if (err.isForbidden) /* not scoped for this target */;
    else if (err.isGone) /* credential expired */;
    else if (err.isRateLimited) /* back off and retry */;
    else if (err.isUnavailable) /* vault fail-closed (503) — deny */;
  }
  throw err;
}
```

### `useCredential(idOrTarget)`

- If `idOrTarget` looks like a **UUID**, it `POST`s straight to the use endpoint.
- Otherwise it's treated as a **target** (e.g. `github.com`): the SDK pages
  through `listCredentials()`, finds the credential whose `target` matches, and
  uses it. If several share a target, the first by listing order wins. If none
  match, it throws `AgentAuthError { status: 404, code: 'not_found' }`.

The returned object is the credential plus the unsealed **`secret`** — the only
SDK return value that carries a secret.

## Proxy mode

When you don't want the secret in your process at all, use **proxy mode**:
AgentAuth makes the downstream request server-side, injects the credential, and
relays the response back. **The raw secret never reaches the agent.** Requires
the agent to hold the `vault:proxy` scope.

```ts
// The host is pinned server-side to the credential's target — you only control
// method/path/query/headers/body. The secret is injected and redacted for you.
const res = await aa.proxy('github.com', { method: 'GET', path: '/user' });

console.log(res.status);            // 200
console.log(res.headers['content-type']);
console.log(res.body);              // downstream body, secret redacted
```

`proxy(idOrTarget, request?)` resolves `idOrTarget` exactly like
`useCredential` (UUID → direct id; otherwise resolved by target via the
listing). `request` defaults to `{ method: 'GET', path: '/' }`; `path` must
start with `/`. A credential whose policy requires approval throws
`ApprovalPendingError` (HTTP 202) — retry after an owner approves.

How the secret is injected downstream is set at deposit time via the optional
`injection` field on `depositCredential` (`bearer` | `basic` | `cookie` |
`{ mode: 'header', name, prefix? }` | `{ mode: 'query', name }`), defaulting to
the server's per-type default.

## Browser login

For sites that can't be driven by a single HTTP call (cookie/header/localStorage
sessions or a real login form), the agent can ask AgentAuth for a **browser-login
plan** and apply it to a [Playwright](https://playwright.dev) or
[Puppeteer](https://pptr.dev) page. The plan carries secret material (cookie
values, header values, storage values, or form-fill values) at the same trust
level as `useCredential` — it flows into the browser only and is never logged.

```ts
import { AgentAuthClient } from '@agentauth/sdk';
import { chromium } from 'playwright'; // or: import puppeteer from 'puppeteer';

const aa = new AgentAuthClient({ baseUrl, apiKey: process.env.AGENTAUTH_KEY! });

const browser = await chromium.launch();
const page = await browser.newPage();

// Fetch the plan and apply it to the page in one call. Returns a NON-SECRET
// summary (names/keys/counts only) — safe to log.
const summary = await aa.browserLogin(page, 'github.com');
console.log(summary);
// e.g. { mode: 'cookie', target: 'github.com', url: 'https://github.com',
//        cookieNames: ['user_session'] }
// the page is now logged in — drive it as usual.
```

The SDK feature-detects the page (Playwright is primary; Puppeteer is a
fallback) and applies the plan per its `mode`:

| `mode`         | What it does                                                          |
| -------------- | -------------------------------------------------------------------- |
| `cookie`       | set cookies on the context/page, then `goto(plan.url)`               |
| `header`       | set extra HTTP headers, then `goto(plan.url)`                        |
| `localStorage` | `goto(plan.url)`, then seed `localStorage` items                     |
| `form`         | run the ordered `goto` / `fill` / `click` actions                   |

Advanced callers can split the two steps: fetch the raw plan with
`getBrowserLoginPlan(idOrTarget)` (resolves `idOrTarget` exactly like
`useCredential`; a policy that needs approval throws `ApprovalPendingError`),
then apply it yourself with the standalone `applyBrowserLogin(page, plan)`. Both
return the same non-secret `BrowserLoginSummary`:
`{ mode, target, url, cookieNames?, headerNames?, storageKeys?, filledFields?, submitted? }`.

### Agent methods

| Method                              | Endpoint                                          |
| ----------------------------------- | ------------------------------------------------- |
| `listCredentials(opts?)`            | `GET /v1/vault/credentials`                       |
| `useCredential(idOrTarget)`         | `POST /v1/vault/credentials/:id/use`              |
| `proxy(idOrTarget, request?)`       | `POST /v1/vault/credentials/:id/proxy`            |
| `getBrowserLoginPlan(idOrTarget)`   | `POST /v1/vault/credentials/:id/browser-login`    |
| `browserLogin(page, idOrTarget)`    | `POST /v1/vault/credentials/:id/browser-login` + applies the plan to `page` |

## Human / admin usage

```ts
import { HumanClient } from '@agentauth/sdk';

// Log in once; the returned client is wired with the session token.
const human = await HumanClient.login('https://vault.example.com', 'me@example.com', 'pw');

const passport = await human.createPassport('work');

await human.depositCredential(passport.id, {
  target: 'github.com',
  label: 'GH token',
  type: 'api_key', // password | oauth_token | cookie | api_key
  secret: 'ghp_xxx',
  // Optional usage policy (all omittable):
  maxUses: 100,                          // cap total uses
  allowedFrom: '2026-01-01T00:00:00Z',   // not usable before (ISO-8601)
  allowedUntil: '2026-12-31T00:00:00Z',  // not usable after  (ISO-8601)
  requireApproval: true,                 // each use needs human approval
});

const agent = await human.issueAgent({
  passportId: passport.id,
  name: 'ci-bot',
  scopes: ['vault:read', 'vault:use', 'target:github.com'],
});
console.log(agent.apiKey); // ⚠️ shown exactly once — capture it now

// Later: revoke instantly (fail-closed).
await human.revokeAgent(agent.id);

// Audit:
const { ok } = await human.verifyAudit(); // server exposes only the integrity boolean
```

You can also register and obtain a raw token without constructing a client:

```ts
await HumanClient.register('https://vault.example.com', 'me@example.com', 'pw');
const session = await HumanClient.loginRaw('https://vault.example.com', 'me@example.com', 'pw');
// session.token / session.expiresAt
```

### Human methods

| Method                                | Endpoint                                |
| ------------------------------------- | --------------------------------------- |
| `HumanClient.register(base,em,pw)`    | `POST /v1/principals`                   |
| `HumanClient.login(base,em,pw)`       | `POST /v1/auth/login` → client          |
| `HumanClient.loginRaw(base,em,pw)`    | `POST /v1/auth/login` → `Session`       |
| `register(em,pw)`                     | `POST /v1/principals`                   |
| `logout()`                            | `POST /v1/auth/logout`                  |
| `createPassport(name)`                | `POST /v1/passports`                    |
| `listPassports(opts?)`                | `GET /v1/passports`                     |
| `depositCredential(passportId,input)` | `POST /v1/passports/:id/credentials`    |
| `listCredentials(passportId,opts?)`   | `GET /v1/passports/:id/credentials`     |
| `issueAgent(input)`                   | `POST /v1/agents`                       |
| `listAgents(opts?)`                   | `GET /v1/agents`                        |
| `revokeAgent(agentId)`                | `POST /v1/agents/:id/revoke`            |
| `bindAgentMtls(agentId,opts)`         | `POST /v1/agents/:id/mtls`              |
| `startOauth(passportId,provider,opts?)` | `POST /v1/passports/:id/oauth/:provider/start` |
| `listAudit(opts?)`                    | `GET /v1/audit`                         |
| `verifyAudit()`                       | `GET /v1/audit/verify`                  |
| `listApprovals(opts?)`                | `GET /v1/approvals`                     |
| `approveRequest(requestId)`           | `POST /v1/approvals/:id/approve`        |
| `denyRequest(requestId)`              | `POST /v1/approvals/:id/deny`           |

## Error handling

Every non-2xx response throws an `AgentAuthError`:

```ts
class AgentAuthError extends Error {
  status: number;        // HTTP status (0 on network failure)
  code: string;          // machine code from the error envelope
  requestId?: string;    // for correlating with server logs / audit
  details?: unknown;     // optional structured details

  isUnauthorized: boolean; // 401
  isForbidden: boolean;    // 403 (scope / target)
  isNotFound: boolean;     // 404
  isGone: boolean;         // 410 (expired)
  isRateLimited: boolean;  // 429
  isUnavailable: boolean;  // 503 (fail-closed)
}
```

If the server returns a non-JSON or empty error body, `code` and `message` fall
back to sensible defaults derived from the status. Network-level failures (DNS,
connection refused, abort) surface as `status: 0`, `code: 'network_error'`.

## Custom `fetch`

Both clients accept an optional `fetch` for tests or non-standard runtimes:

```ts
new AgentAuthClient({ baseUrl, apiKey, fetch: myFetch });
```

## Build & test

```bash
pnpm build   # tsc → dist/ (with .d.ts)
pnpm test    # vitest unit tests (global fetch is mocked; no network)
```

## License

MIT
