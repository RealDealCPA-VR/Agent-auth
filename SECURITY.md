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
