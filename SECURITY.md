# Security Policy

AgentAuth is a credential vault. Security is the product, so we treat it that way.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers by opening a
[GitHub security advisory](https://github.com/RealDealCPA-VR/Agent-auth/security/advisories/new).
Do **not** open public issues for security reports. We aim to acknowledge within
72 hours.

## Design guarantees

- **Envelope encryption.** A master key (KEK) wraps a per-passport data key
  (DEK); each credential is sealed with AES-256-GCM under its passport's DEK,
  bound to `passport:target` via AAD. One compromised passport never exposes
  another.
- **Secrets at rest only.** Plaintext secrets exist only transiently in memory
  during an explicit, scoped, audited `use` call. They are never logged, never
  written to the audit trail, and never returned by any other endpoint.
- **Fail closed.** If the authorization store is unreachable, agent requests are
  denied (`503`), never default-allowed. Revocation is checked on every call.
- **Least authority.** Agents are bound to exactly one passport and gated by
  scopes (`vault:read`, `vault:use`, `target:<host>`). Per-credential policies add
  max-use counts, time windows, and human approval gates.
- **Tamper-evident audit.** Every security event is appended to a forward-linked
  HMAC hash-chain; `/v1/audit/verify` recomputes the chain to detect any
  insert/update/reorder or deletion of an *interior* row. (A forward chain
  cannot, by itself, detect **tail-truncation** — deletion of the newest
  contiguous rows leaves every surviving link self-consistent and needs no key.)
  Prevention of any deletion, including tail-truncation, is enforced by database
  triggers that block UPDATE/DELETE/TRUNCATE on the normal SQL path; this is
  preventive only against a role that cannot disable triggers — a table
  owner/superuser can `DISABLE TRIGGER`, so **run the runtime under a
  least-privilege, non-owner DB role** (INSERT/SELECT only, no TRUNCATE/DDL) and
  keep a separate owner role for migrations.

## Proxy mode (the secret never leaves the vault)

`POST /v1/vault/credentials/:id/proxy` lets an agent act *through* a credential
without ever receiving it — AgentAuth performs the downstream request itself.
It is gated by the dedicated `vault:proxy` scope (issuable **without** `vault:use`,
so an agent can proxy through credentials it can never read), and carries its own
guarantees:

- **Host pinned to the target.** The downstream host is fixed server-side to the
  credential's target; the agent only supplies method/path/query/headers/body. It
  cannot repoint the request to an attacker-controlled host, so the injected secret
  cannot be exfiltrated (no SSRF/exfil pivot).
- **Injection is server-controlled.** The credential is injected per the
  credential's configured `injection` mode (bearer/basic/cookie/header/query). The
  agent **cannot override or strip** the injected auth — supplied headers can't
  displace it.
- **Redirects are not followed.** A 3xx is returned as-is; AgentAuth never re-issues
  the request (with the secret) against a `Location` it didn't pin.
- **No plaintext HTTP to non-loopback.** Proxying a secret over cleartext `http://`
  to a non-loopback host is refused unless `PROXY_ALLOW_HTTP=true`.
- **No private/metadata hosts.** Requests to private, link-local, and cloud
  metadata addresses are refused unless `PROXY_ALLOW_PRIVATE=true` — checked both
  as a literal (including bracketed/IPv4-mapped IPv6 and decimal/hex/octal IPv4
  encodings) **and after DNS resolution**, so a public name that resolves to a
  private/metadata address is rejected too. The connection is **pinned to the
  validated IP addresses** (a custom DNS `lookup` reused for both the check and
  the socket), so a name that *rebinds* between check and connect can't reach a
  private address either — the socket only dials addresses that passed validation.
- **Secret redacted from the response.** The returned `body` **and** response
  headers have the injected secret (and its base64 form) redacted best-effort,
  case-insensitively, so a downstream that reflects the credential (e.g. in
  `Set-Cookie` or an echoed header) can't hand it back. This is defense in depth
  behind the primary invariant: the secret is only ever injected server-side and
  is never sent to the agent in the first place.
- **Same policy envelope as `use`.** Scope/target checks, max-use counts, time
  windows, approval gates, OAuth refresh, and audit logging all still apply; a
  bounded timeout (`PROXY_TIMEOUT_MS`) and response cap (`PROXY_MAX_RESPONSE_BYTES`)
  bound the call.

## Browser-login mode (secret-bearing plan, confined to the SDK)

`POST /v1/vault/credentials/:id/browser-login` turns a credential into a concrete
browser-login plan (cookies/header/`localStorage`/form actions) so an agent that
drives a real browser can authenticate to a web app. Unlike proxy mode, **this
plan carries secret material** — it is the **same `vault:use` trust level as
`/use`**, not the never-reaches-agent `vault:proxy` path. The meaningful boundary
is the **SDK helper** (`browserLogin`): it applies the plan to a `page` object,
confines the secret to the SDK process's memory, and returns only a non-secret
summary — the secret is never handed up to the agent's reasoning/LLM layer, and
the server audits `mode` + `target` only (never the plan or secret). If you need
the strict "the secret never reaches the agent" guarantee, use **proxy mode**;
browser-login is the path for web apps that cannot be driven over plain HTTP. The
non-secret spec lives in the credential's `metadata.browser` (a `password`
credential requires an explicit `form` spec). This preserves scope separation:
browser-login requires `vault:use`, so an agent issued only `vault:proxy` cannot
obtain a secret-bearing plan.

**Raw-plan path (`vault:browser:raw`).** The server returns the same secret-bearing
plan whether or not the SDK confines it — so `vault:use` is what gates secret
*exposure*, and `vault:browser:raw` gates the *self-handoff affordance*. The
`browserLogin(page, …)` helper (which applies the plan and keeps the secret out of
the agent's reasoning) needs only `vault:use`. The explicit `getBrowserLoginPlan` /
`POST …/browser-login?raw=true` path — which returns the plan to the caller to hold
itself — additionally requires the **off-by-default `vault:browser:raw`** scope
(`403 missing_scope` without it; an off-by-default checkbox at agent-issue time), so
the liability path is opt-in per agent. The MFA self-handoff helper `resolveMfa`
likewise injects the human-approved one-time code into the DOM and never returns it.

## Additional controls

- **KMS-backed keys.** With `KEY_PROVIDER=kms`, the master key never enters the
  process — per-passport DEKs are wrapped/unwrapped by an external KMS.
- **Versioned key rotation.** The KEK, JWT signing key, and audit HMAC key are
  each versioned (per-record key id) and rotate with zero downtime — old data and
  in-flight tokens keep verifying. See [docs/ROTATION.md](./docs/ROTATION.md).
- **OAuth tokens.** Captured access **and** refresh tokens are sealed like any
  other credential; refresh happens server-side under an advisory lock and the
  refresh token is never returned to an agent — only the short-lived access token.
  Proactive refresh requires the provider to return `expires_in` so expiry is
  known; a provider that omits it is treated as freshness-unknown and is not
  proactively refreshed.
- **mTLS identity.** Agents may authenticate with a client certificate (native or
  proxy-terminated); the cert fingerprint maps to the agent, fail-closed.
- **Anti-abuse.** Argon2id hashing, constant-time login, per-route rate limits,
  strict body/size/scope validation, security headers, and a uniform error
  envelope that never leaks internals.

## Operational requirements

- `MASTER_KEY` and `JWT_SECRET` must be supplied via the environment and never
  committed. Losing `MASTER_KEY` makes all stored credentials unrecoverable —
  back it up in a KMS/secret manager.
- Always run behind TLS in production and set `NODE_ENV=production`.
- Rotate `MASTER_KEY` and agent keys periodically (see key-version support).
