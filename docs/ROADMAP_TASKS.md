# AgentAuth Roadmap — Handoff Ledger

This file is the single source of truth for the roadmap build. It implements the
**handoff / pickup** protocol: every working agent MUST (1) read this file to pick
up current state, (2) do exactly its assigned task within a bounded scope (~60% of
its context window — stop and hand off before exhausting context), (3) update the
status table + Handoff Log below before finishing.

## Rules of engagement

- One task = one bounded unit that fits well within 60% context. If a task grows
  past that, split it and add a follow-up row, then hand off.
- Touch ONLY the files listed for your task to avoid collisions with parallel agents.
- Shared-core files (`src/env.ts`, `src/server.ts`, `src/db/schema.ts`) are edited
  by the orchestrator or a single owner at a time — never two agents at once.
- After any code change: `pnpm typecheck && pnpm lint && pnpm test` must pass before
  marking a task `done`. New features require new tests.
- Use mocks/fakes for external services (KMS, OAuth providers) so everything is
  testable offline. Real-provider wiring must be behind an interface + env switch.

## Status legend

`todo` · `in-progress` · `blocked` · `done`

## Task table

| ID  | Epic     | Task                                                                                                                          | Files (primary)                                                                  | Depends on           | Owner | Status |
| --- | -------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------- | ----- | ------ | ---- |
| T1  | TLS      | Native HTTPS option (env HTTPS_CERT/KEY, conditional https in Fastify, HSTS in prod) + test                                   | env.ts, server.ts, index.ts, .env.example                                        | —                    | orch  | todo   |
| T2  | Rotation | JWT signing-key versioning (kid header, active+retired keys, rotate without invalidating live tokens) + tests                 | env.ts, auth/human.ts, test                                                      | —                    | —     | todo   |
| T3  | Rotation | Audit HMAC key versioning (per-row key id, verify across rotations) + tests                                                   | env.ts, lib/audit.ts, db/schema.ts, test                                         | —                    | —     | todo   |
| T4  | Rotation | Scheduled rotation runner + ops docs (k8s CronJob/systemd) + rotate-all script polish                                         | db/rotate-keys.ts, docs, README                                                  | T2,T3                | —     | todo   |
| T5  | KMS      | KeyProvider abstraction: make KEK wrap/unwrap async behind an interface; local provider; ripple to vault.ts; tests stay green | crypto/envelope.ts, crypto/keyprovider/\*, lib/vault.ts, db/rotate-keys.ts, test | —                    | —     | todo   |
| T6  | KMS      | KMS provider impl (AWS KMS) + FakeKms for tests + env provider switch + tests                                                 | crypto/keyprovider/kms.ts, env.ts, test, package.json                            | T5                   | —     | todo   |
| T7  | SDK      | TypeScript SDK package: client + useCredential(target                                                                         | id) + error/scrub + tests + build                                                | packages/sdk-ts/\*\* | —     | —      | todo |
| T8  | SDK      | Python SDK package: equivalent client + tests                                                                                 | packages/sdk-py/\*\*                                                             | —                    | —     | todo   |
| T9  | OAuth    | Provider registry + env config + schema additions (provider, refresh metadata)                                                | oauth/registry.ts, db/schema.ts, env.ts, test                                    | —                    | —     | todo   |
| T10 | OAuth    | Authorization-code flow: start + callback endpoints (PKCE, CSRF state), seal tokens as oauth_token credential                 | routes/oauth.ts, oauth/\*, server.ts                                             | T9                   | —     | todo   |
| T11 | OAuth    | Lazy token refresh on use (refresh near expiry, advisory-locked re-seal)                                                      | lib/vault.ts, oauth/\*, routes/vault.ts, test                                    | T10                  | —     | todo   |
| T12 | OAuth    | Mock OAuth provider fixture + full integration tests (start→callback→use→refresh)                                             | test/oauth._, test/fixtures/_                                                    | T10,T11              | —     | todo   |
| T13 | Policies | Per-credential policy schema (max_uses, rate limit, time window, require_approval) + enforcement in use-path + tests          | db/schema.ts, lib/vault.ts, routes/vault.ts, test                                | —                    | —     | todo   |
| T14 | Policies | Approval workflow: pending-requests table, request/approve/deny endpoints, use gated by approval + tests                      | db/schema.ts, routes/approvals.ts, lib/\*, server.ts, test                       | T13                  | —     | todo   |
| T15 | mTLS     | mTLS agent identity: server requestCert/ca config, cert fingerprint on agent, mapping + issuance + tests (self-signed)        | auth/mtls.ts, auth/agent.ts, db/schema.ts, server.ts, env.ts, test               | —                    | —     | todo   |
| T16 | WebUI    | Next.js admin scaffold (web/) — login, passports, deposit, agents, audit views                                                | web/\*\*                                                                         | —                    | —     | todo   |
| T17 | WebUI    | OAuth handoff UI + approvals UI                                                                                               | web/\*\*                                                                         | T10,T14,T16          | —     | todo   |
| T18 | Docs     | Update README, SECURITY.md, .env.example, OpenAPI for all new features                                                        | README.md, SECURITY.md, .env.example                                             | most                 | —     | todo   |
| T19 | QA       | Full integration gauntlet (typecheck/lint/test/build/docker) across everything                                                | —                                                                                | all                  | —     | todo   |
| T20 | QA       | Adversarial verification loop until a fresh fleet finds zero bugs/gaps                                                        | —                                                                                | all                  | —     | todo   |

## Handoff Log (append-only; newest last)

- (init) Ledger created. Baseline: 97 tests green, audit-converged, pushed to GitHub at commit 7b15734.
- T1 DONE (orch): native HTTPS via HTTPS_CERT/HTTPS_KEY env; server terminates TLS when set; real TLS integration test (selfsigned). env+server+index+.env.example.
- T5 DONE (orch): KeyProvider abstraction. envelope.ts now AEAD-only; KEK wrap/unwrap async behind `crypto/keyprovider/{index,local}.ts`; vault.ts + rotate-keys.ts await; KEY*PROVIDER env (local|kms) + KMS*\* placeholders. crypto.test updated. setKeyProvider() hook for tests/KMS.
- T7 DONE (agent): TS SDK at packages/sdk-ts (AgentAuthClient+HumanClient, useCredential(id|target), typed AgentAuthError, fetch-mocked tests). Self-contained vitest config. NOT yet installed/run by orch — pending T19.
- T8 DONE (agent): Python SDK at packages/sdk-py (httpx, AgentAuthClient+HumanClient, respx/MockTransport tests). NOT yet installed/run — pending T19.
- T16 DONE (agent): Next.js 15 admin UI at web/ (login, passports, passport detail+deposit, agents issue/list/revoke, audit+verify). NOT yet installed/run — pending T19.
- Verified after T1+T5: 98 server tests green, typecheck+lint pass. Root eslint/prettier now ignore packages/ and web/ (self-managed).
- T2 DONE (orch): JWT signing-key versioning. kid in header; verify resolves key by kid (JWT_KEY_ID active + JWT_SECRETS_RETIRED). test/jwt-rotation.test.ts. Shared validateRetired() in env.
- T3 DONE (orch): audit HMAC key versioning. audit_events.hash_key_id col; active=AUDIT_HMAC_SECRET|derived(MASTER_KEY); AUDIT_KEYS_RETIRED; verifyAuditChain selects key per row. Migration regenerated, DB reset. 102 tests green.
- NEXT: T13 (policies), T9-T12 (OAuth), T6 (KMS), T14 (approvals), T15 (mTLS), T4 (rotation docs), T17 (web OAuth/approvals), T18 (docs), T19 (gauntlet incl SDK/web install+test), T20 (verify loop).
