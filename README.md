<div align="center">

# 🛂 AgentAuth

### The Agent Passport — log in once, let your agents in forever.

**A credential vault and identity broker built for the age of autonomous AI.**
Your agent authenticates **once**. After that, it can securely act as you —
everywhere — without ever holding your raw secrets.

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![Node](https://img.shields.io/badge/node-20+-339933?logo=node.js&logoColor=white)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](#)
[![Crypto](https://img.shields.io/badge/crypto-AES--256--GCM%20envelope-blueviolet)](#)
[![Fail](https://img.shields.io/badge/posture-fail--closed-critical)](#)
[![License](https://img.shields.io/badge/license-MIT-black)](#)

</div>

---

## The problem nobody solved

AI agents are getting terrifyingly capable — and they're stuck at the front door.

Every agent that wants to _do_ something real hits the same wall: **login**.
Today the "solutions" are all bad:

- 🔓 **Paste your password into a prompt.** Now it's in a model's context, a log, a trace.
- 🗝️ **Hand the agent a `.env` full of API keys.** One leak and everything's gone.
- 🤷 **Re-authenticate on every run.** Doesn't scale, breaks automation, drives you insane.

You shouldn't have to choose between _capable agents_ and _not getting owned_.

## The idea: a passport for your agent

> **You** log in once, manually. AgentAuth seals those credentials into a
> **passport**. From then on, your **agent** presents its own key and gets exactly
> the access you granted — scoped, time-boxed, revocable, and logged — and the raw
> secret is unsealed only for the instant it's used.

It's a password manager, an OAuth broker, and an audit system — re-imagined as an
**identity layer for machines**.

```
 You (once)                    AgentAuth                         Your Agent (forever)
 ──────────                    ─────────                         ────────────────────
 deposit creds  ───────────▶  🔒 sealed in your passport
 mint agent key ───────────▶  🤖 bound to passport + scopes ──▶  aa_… (shown once)
                                                                  │
                               "what can I use?"  ◀───────────────┤  discovers (scoped)
                               🔓 unseal + audit  ◀───────────────┤  logs into anything
                               revoke / expire    ✋               │
```

---

## Why it's safe (the part that matters)

AgentAuth is a vault, so it's engineered like one. Security isn't a feature here —
it's the whole product.

### 🔐 Envelope encryption, per passport

A master key (KEK) wraps a **unique data key for every passport**; every credential
is sealed with **AES-256-GCM** (random nonce, auth tag, and `passport:target` AAD
binding). Crack one passport and you've learned _nothing_ about any other. Keys are
**versioned and rotatable** — old data stays readable while you roll forward.

### ✋ Fail-closed, always

If the authorization store is unreachable, agents are **denied** (`503`) — never
default-allowed. Revocation flips a flag checked on **every single request**.
There is no "fail open" path. We tested it: pull the database, access stops.

### 🧾 A tamper-evident audit trail

Every issue, deposit, use, revoke, and denial is appended to an **HMAC hash-chained**
log. Change one row and the chain breaks — detectably. Triggers block
`UPDATE`/`DELETE`/`TRUNCATE` on the table via the normal SQL path (run the runtime
under a least-privilege DB role so it can't disable them — see
[SECURITY.md](./SECURITY.md)). Secrets never touch the log.

### 🎯 Least authority by default

Agents are bound to one passport and gated by **scopes** (`vault:read`, `vault:use`)
and **target globs** (`target:github.com`, `target:*.internal`). A narrowly-scoped
agent can't even _enumerate_ the credentials it isn't allowed to touch.

### 🚇 Proxy mode — the secret never reaches the agent

`use` hands the unsealed secret back to the agent. **Proxy mode never does.**
With `POST /v1/vault/credentials/:id/proxy`, AgentAuth makes the downstream call
**server-side**, injects the credential into that request, and returns only the
downstream response — with the secret **redacted from the body**. The agent
chooses the method/path/query/headers/body; the **host is pinned** to the
credential's target server-side, so the agent can't repoint the request to
exfiltrate the secret.

```bash
# Agent presents its own key; AgentAuth calls github.com with the sealed token injected.
curl -s $BASE/v1/vault/credentials/$CRED/proxy -X POST \
  -H "authorization: Bearer $APIKEY" -H 'content-type: application/json' \
  -d '{"method":"GET","path":"/user","headers":{"accept":"application/vnd.github+json"}}'
# → { "status": 200, "headers": {...}, "body": "{...}" }   the raw token is never in the response
```

This needs the **`vault:proxy`** scope. Injection is configured **per credential**
at deposit time (`injection`: `bearer` · `basic` · `cookie` · `header` ·
`query`), so AgentAuth knows exactly where the secret goes. Because proxy mode
returns no secret, you can issue **proxy-only agents** — grant `vault:proxy`
**without** `vault:use` and the agent can act through credentials it can never read.

### 🛡️ Hardened on every layer

Argon2id password & key hashing · constant-time login (no user enumeration) ·
per-route **rate limiting** & brute-force / argon2-DoS protection · session
revocation (`jti` denylist) · Helmet security headers · CORS allowlist ·
strict body limits · Zod validation everywhere · request-id correlation ·
no stack-trace leakage · fail-fast secret validation (won't even boot insecure).

---

## ⚡ Quickstart (Docker only — no host toolchain)

```bash
cp .env.example .env
# Generate two 32-byte base64 secrets. With openssl (no Node needed):
echo "MASTER_KEY=$(openssl rand -base64 32)" >> .env
echo "JWT_SECRET=$(openssl rand -base64 32)" >> .env
# …or, if you have neither openssl nor host Node, use the Docker image you're
# about to build:  docker run --rm node:22-alpine node -e \
#   "console.log(require('crypto').randomBytes(32).toString('base64'))"
# ↑ edit .env so each key appears once. Save .env as UTF-8 **without a BOM**.

docker compose up -d --build     # app + db + auto-migrate → http://localhost:8080
docker compose exec app node dist/cli/bootstrap.js   # prints a ready-to-use AGENT API KEY
```

That's it: `docker compose up` brings up the database, applies migrations, and
serves the API; the in-container `bootstrap.js` mints a principal, a passport, and
an agent key you can hand straight to an agent (via the **MCP server**, an **SDK**,
or raw HTTP). On a host with the toolchain installed (`pnpm install`) you can run
`pnpm agentauth:init` instead.

<details><summary>Local dev (no Docker for the app)</summary>

```bash
pnpm install
pnpm db:up                       # Postgres in Docker (port 5433)
cp .env.example .env             # + MASTER_KEY / JWT_SECRET as above
pnpm db:generate && pnpm db:migrate
pnpm dev                         # http://localhost:8080  •  docs at /docs
```

</details>

Interactive OpenAPI docs are served at **`/docs`**. Liveness `/healthz`,
readiness `/readyz`, Prometheus metrics `/metrics`.

## 🎬 The whole story in one script

```bash
BASE=http://localhost:8080

# 1) You — register & log in (once)
curl -s $BASE/v1/principals -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery"}'
TOKEN=$(curl -s $BASE/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery"}' | jq -r .token)

# 2) You — open a passport and deposit a credential (the manual login)
PASSPORT=$(curl -s $BASE/v1/passports -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"work"}' | jq -r .id)
curl -s $BASE/v1/passports/$PASSPORT/credentials -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"target":"github.com","label":"GH token","type":"api_key","secret":"ghp_xxx"}'

# 3) You — mint a scoped agent key (shown exactly once)
APIKEY=$(curl -s $BASE/v1/agents -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"passportId\":\"$PASSPORT\",\"name\":\"ci-bot\",\"scopes\":[\"vault:read\",\"vault:use\",\"target:github.com\"]}" \
  | jq -r .apiKey)

# 4) Your agent — logs into anything, no human in the loop
CRED=$(curl -s $BASE/v1/vault/credentials -H "authorization: Bearer $APIKEY" | jq -r '.items[0].id')
curl -s $BASE/v1/vault/credentials/$CRED/use -X POST -H "authorization: Bearer $APIKEY"
# → the sealed secret, unsealed for use, fully audited

# 5) You — changed your mind? Revocation is instant and fail-closed.
curl -s $BASE/v1/agents/<agentId>/revoke -X POST -H "authorization: Bearer $TOKEN"
```

---

## 🗺️ API at a glance

| Area      | Endpoint                                                             | Who       |
| --------- | -------------------------------------------------------------------- | --------- |
| Identity  | `POST /v1/principals`, `POST /v1/auth/login`, `POST /v1/auth/logout` | Human     |
| Passports | `POST/GET /v1/passports`                                             | Human     |
| Deposit   | `POST/GET /v1/passports/:id/credentials`                             | Human     |
| Agents    | `POST/GET /v1/agents`, `POST /v1/agents/:id/revoke`                  | Human     |
| **Vault** | `GET /v1/vault/credentials`, `POST /v1/vault/credentials/:id/use`    | **Agent** |
| **Proxy** | `POST /v1/vault/credentials/:id/proxy` (secret-free; `vault:proxy`)  | **Agent** |
| Audit     | `GET /v1/audit`, `GET /v1/audit/verify`                              | Human     |
| Ops       | `GET /healthz`, `/readyz`, `/metrics`, `/docs`                       | —         |

## 🧱 Architecture

```
src/
  env.ts            fail-fast config (refuses to boot without real secrets)
  server.ts         Fastify: helmet · cors · rate-limit · swagger · error envelope · request-id
  crypto/
    envelope.ts     AES-256-GCM envelope encryption · key versioning + rotation
    secrets.ts      argon2id hashing · agent key format · constant-time helpers
  auth/
    human.ts        session JWTs (jti) + fail-closed revocation
    agent.ts        fail-closed agent auth · scope + target enforcement
  lib/
    vault.ts        deposit / unseal (transient DEK handling, buffer scrubbing)
    audit.ts        HMAC hash-chained, tamper-evident audit log + verifier
    http.ts         one error envelope · pagination
    metrics.ts      Prometheus counters
  db/schema.ts      principals · passports · credentials · agents · revoked_sessions · audit_events
  routes/           principals · passports · agents · vault · audit · guards
```

## 🧪 Tested like a vault — 170 tests, all green

- **Crypto unit tests** — round-trips, tamper rejection, AAD binding, wrong-key
  failure, format-version & algorithm checks, key-id tagging, rotation.
- **Integration tests (Fastify `inject` + ephemeral Postgres)** — every route, plus
  the properties that actually matter:
  cross-tenant isolation (IDOR), scope & target enforcement, revocation fail-closed,
  database-down fail-closed, user-enumeration resistance, audit completeness,
  hash-chain tamper detection, and append-only enforcement.

Built under adversarial review: a fleet of independent agents audited the code
(99 findings), every one was fixed, then a second fleet tried to _disprove_ each
fix line-by-line. The gaps they found were closed and re-verified.

```bash
pnpm test        # unit + integration (Vitest + Fastify inject + ephemeral Postgres)
pnpm typecheck   # strict TS, no any-escapes
pnpm lint        # eslint clean
pnpm build       # production build (no source maps)
```

CI runs typecheck → lint → migrate → test → build → Docker image on every push.

## 🚀 Deploy

```bash
docker build -t agentauth .
docker run -p 8080:8080 --env-file .env agentauth   # runs as non-root, healthchecked
```

Production turns on Postgres TLS by default, locks CORS to your allowlist, enables
CSP, and validates that every secret is present and well-formed before accepting a
single request.

## 🧩 Ecosystem

- **MCP server** — [`packages/mcp-server`](./packages/mcp-server): drop-in Model Context Protocol server exposing `list_credentials`, `use_credential`, and `proxy_request` (secret-free proxy mode) tools. Point any MCP-capable agent (Claude Desktop, etc.) at it with `AGENTAUTH_API_KEY` and your agents get the vault as tools — **zero code**.
- **TypeScript SDK** — [`packages/sdk-ts`](./packages/sdk-ts): `new AgentAuthClient({ baseUrl, apiKey })` then `await client.useCredential('github.com')`. Plus a `HumanClient` for the management API.
- **Python SDK** — [`packages/sdk-py`](./packages/sdk-py): the same surface (`AgentAuthClient`, `HumanClient`) over `httpx`.
- **Admin web UI** — [`web/`](./web): a Next.js console for login, passports, credential deposit, agent issuance/revocation, the approvals queue, OAuth connect, and the audit trail.
- **Runnable examples** — [`examples/`](./examples): copy-paste TS + Python agents that fetch and use a credential.

## ✅ What ships today

- 🔐 **KMS-backed keys** — `KEY_PROVIDER=kms` keeps the master key in AWS KMS; the in-process key never holds it. Local AES-GCM KEK is the default.
- 🔁 **Zero-downtime key rotation** — KEK, JWT signing key, and audit HMAC key are all versioned and rotatable. See the [rotation runbook](./docs/ROTATION.md); the re-wrap runs via `pnpm db:rotate` (local) / `node dist/db/rotate-keys.js` (in the shipped image).
- 🪪 **OAuth credential capture** — authorize a provider in the browser once (PKCE auth-code); AgentAuth seals the tokens and **transparently refreshes** them when an agent uses the credential.
- 📜 **Per-credential policies** — max-uses, time windows, and **human approval workflows** (request → approve → single-use grant) gate sensitive credentials.
- 🌐 **mTLS agent identity** — agents can authenticate with a client certificate (native or proxy-terminated) instead of a bearer key.
- 🔌 **TLS termination** — native HTTPS (`HTTPS_CERT`/`HTTPS_KEY`) or front it with a proxy.

## 🔭 Roadmap

- ⏳ Scheduled credential-expiry sweeps & richer approval notifications
- 🧭 OIDC discovery + more first-class OAuth providers out of the box
- 📊 Built-in dashboards on top of `/metrics`

## 📄 License

MIT. See [SECURITY.md](./SECURITY.md) for the security policy and design guarantees.

<div align="center">

**AgentAuth** — because your agents deserve a passport, not your password.

</div>
