# Security Policy

AgentAuth is a credential vault. Security is the product, so we treat it that way.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers (open a
GitHub security advisory, or email the address in `package.json`). Do **not**
open public issues for security reports. We aim to acknowledge within 72 hours.

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
- **Tamper-evident audit.** Every security event is appended to an HMAC
  hash-chain; the table is append-only at the database level and `/v1/audit/verify`
  recomputes the chain to detect any insert/update/delete.

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

## Additional controls

- **KMS-backed keys.** With `KEY_PROVIDER=kms`, the master key never enters the
  process — per-passport DEKs are wrapped/unwrapped by an external KMS.
- **Versioned key rotation.** The KEK, JWT signing key, and audit HMAC key are
  each versioned (per-record key id) and rotate with zero downtime — old data and
  in-flight tokens keep verifying. See [docs/ROTATION.md](./docs/ROTATION.md).
- **OAuth tokens.** Captured access **and** refresh tokens are sealed like any
  other credential; refresh happens server-side under an advisory lock and the
  refresh token is never returned to an agent — only the short-lived access token.
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
