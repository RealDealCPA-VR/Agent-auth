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
log. Change one row and the chain breaks — detectably. The table is **append-only at
the database level** (a trigger blocks `UPDATE`/`DELETE`). Secrets never touch the log.

### 🎯 Least authority by default

Agents are bound to one passport and gated by **scopes** (`vault:read`, `vault:use`)
and **target globs** (`target:github.com`, `target:*.internal`). A narrowly-scoped
agent can't even _enumerate_ the credentials it isn't allowed to touch.

### 🛡️ Hardened on every layer

Argon2id password & key hashing · constant-time login (no user enumeration) ·
per-route **rate limiting** & brute-force / argon2-DoS protection · session
revocation (`jti` denylist) · Helmet security headers · CORS allowlist ·
strict body limits · Zod validation everywhere · request-id correlation ·
no stack-trace leakage · fail-fast secret validation (won't even boot insecure).

---

## ⚡ Quickstart (60 seconds)

```bash
pnpm install
pnpm db:up                       # Postgres in Docker (port 5433)

cp .env.example .env
node -e "console.log('MASTER_KEY='+require('crypto').randomBytes(32).toString('base64'))" >> .env
node -e "console.log('JWT_SECRET='+require('crypto').randomBytes(32).toString('base64'))" >> .env
# ↑ edit .env so each key appears once

pnpm db:generate && pnpm db:migrate
pnpm dev                         # http://localhost:8080  •  docs at /docs
```

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

## 🧪 Tested like a vault — 80 tests, all green

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

## 🔭 Roadmap

- 🔁 Key rotation **ships today** via `pnpm db:rotate` (re-wraps every passport DEK
  under a new active KEK); next up: scheduled, zero-downtime rotation sweeps
- 🪪 OAuth/OIDC credential capture flows ("log in once" via browser handoff)
- 📜 Per-credential usage policies & approval workflows
- 🌐 mTLS agent identity option
- 🧩 SDKs for the agent side (`useCredential(target)` in one line)

## 📄 License

MIT. See [SECURITY.md](./SECURITY.md) for the security policy and design guarantees.

<div align="center">

**AgentAuth** — because your agents deserve a passport, not your password.

</div>
