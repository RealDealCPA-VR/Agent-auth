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
const { ok, brokenAtSeq } = await human.verifyAudit();
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
| `listAudit(opts?)`                    | `GET /v1/audit`                         |
| `verifyAudit()`                       | `GET /v1/audit/verify`                  |

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
