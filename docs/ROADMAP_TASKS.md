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
| T14 | Policies | Approval workflow: pending-requests table, request/approve/deny endpoints, use gated by approval + tests                      | db/schema.ts, routes/approvals.ts, lib/\*, server.ts, test                       | T13                  | orch  | done   |
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
- T9-T12 DONE (agent): OAuth authorization-code credential capture + lazy refresh. env adds OAUTH_PROVIDERS (JSON registry, validated in superRefine), OAUTH_REDIRECT_BASE, OAUTH_STATE_TTL_SECONDS (default 600). New `oauth_flows` table (state unique + idx, PKCE codeVerifier, principal/passport/provider/target/label, expiresAt). src/oauth/{registry.ts getProvider/redirectUri, tokens.ts PKCE/state/exchange/refresh/needsRefresh(60s skew)/buildAuthorizeUrl}. src/routes/oauth.ts: POST /v1/passports/:id/oauth/:provider/start (requireHuman, ownership, returns {authorizeUrl,state}) + GET /v1/oauth/callback (no auth, state lookup, code exchange, seals BOTH tokens as JSON {access_token,refresh_token,token_type,scope,expires_at} into an oauth_token credential, metadata={provider,scope,tokenExpiresAt}, deletes flow). vault.useCredential: oauth_token unseals token set, refreshes near-expiry under pg_advisory_xact_lock(ns,credHash) with re-read-under-lock, re-seals, returns only access_token; new UseResult 'refresh_failed' -> route 502 oauth_refresh_failed. audit enum +oauth.start/oauth.capture. server registers oauthRoutes. test/fixtures/mock-oauth-provider.ts (node:http, /authorize+/token, refresh rotates access token, failNextToken). test/oauth.test.ts (6 cases). Migration regenerated (drizzle/0000_funny_abomination.sql), DB volume reset. 118 tests green (was 112). NOTE: callback returns success JSON (no redirect); refresh with missing provider/refresh_token degrades to returning current token (not a hard fail).
- T14 DONE (orch): human approval workflow. New `approval_status` enum + `approval_requests` table (passportId idx + (credentialId,agentId,status) idx; cascade FKs to credentials/passports/agents). env APPROVAL_TTL_SECONDS (default 900). lib/approvals.ts: requestOrConsume (single-use atomic consume, TTL-bounded, re-requests when stale/consumed), listPending, approve/deny (ownership via passport join, pending-only, approve refreshes TTL). useCredential signature now (passportId, id, {agentId}); approval resolved BEFORE reserving a maxUses slot; UseResult adds approval_pending/approval_denied (removed approval_required). routes/vault.ts: pending -> 202 {status:'pending',requestId} (audited success:false), denied -> 403 approval_denied. New routes/approvals.ts (requireHuman): GET /v1/approvals (paginated, owned-scoped, empty page if none owned), POST /v1/approvals/:id/{approve,deny} (404 if not found/owned, audited approval.approve/approval.deny). Migration regenerated (drizzle/0000_sudden_daredevil.sql), DB volume reset. 112 tests green (was 102; +approvals.test.ts 3 cases, policies test updated to 202).
- T6 DONE: KMS KeyProvider (lazy @aws-sdk/client-kms via non-literal import; alg 'KMS' wrap) + offline FakeKmsKeyProvider; getActiveKeyId() now lazy; KEY_PROVIDER=kms wiring. test/kms.test.ts exercises vault end-to-end through FakeKms.
- T15 DONE (agent): mTLS agent identity. agents.certFingerprint (unique idx). env MTLS_ENABLED/MTLS_CA/MTLS_TRUSTED_PROXY/MTLS_FP_HEADER. src/auth/mtls.ts (fingerprintFromPem, extractClientFingerprint native|proxy, authenticateAgentByCert fail-closed). guards.requireAgent: bearer primary, mTLS fallback. POST /v1/agents/:id/mtls binds a cert (ownership-checked). server adds requestCert/rejectUnauthorized:false/ca when native. test/mtls.test.ts (proxy-header path + fingerprintFromPem).
- T7/T8/T16/T17 DONE (agents): TS SDK (packages/sdk-ts, 30 tests), Python SDK (packages/sdk-py, 26 tests), Next.js web (web/, 11 tests + prod build) incl approvals queue + OAuth connect.
- T18 DONE: README (ecosystem + shipped features), SECURITY.md (new controls), .env.example (all knobs). T4 DONE: docs/ROTATION.md runbook.
- T19 DONE: full monorepo gauntlet green — server 127 + prod build + docker build; SDK-TS 30; SDK-PY 26; web 11 + next build. Fixed web logout (best-effort) + api.test typing during integration.
- T20 DONE: adversarial verification loop converged. r1=4 fixed (vault expiresAt, approvals stale-read tx+FOR UPDATE, SDK 202 ApprovalPendingError x2, web localStorage guards); r2=0; r3=1 fixed (approve/deny return full ApprovalRequest); r4=3 fixed (deny TTL refresh, SDK approval methods x2); r5=1 fixed (web decidedAt type); r6=0; r7=0 real (1 disproven false positive re: drizzle inArray-subquery, refuted by passing approve->200 test; added clarifying comment). Two consecutive clean rounds.
- FINAL: 194 tests across monorepo (server 127, sdk-ts 30, sdk-py 26, web 11); typecheck/lint/prod build/docker build all green. ALL 20 ROADMAP TASKS COMPLETE.

## Plug-and-play pass (2026-06-15)

- P1 DONE (orch): full-stack `docker compose up` — added `app` service (build, depends_on db healthy, env_file .env, DATABASE_URL=db:5432 override, command `node dist/db/migrate.js && node dist/index.js`, port 8080). Verified: build+up → /readyz ready. Caught+fixed a real blocker: .env had a UTF-8 BOM that breaks compose env_file (strip to UTF-8 no-BOM; noted in README/.env.example).
- P2 DONE (orch): bootstrap CLI src/cli/bootstrap.ts + `pnpm agentauth:init` — creates principal+passport+agent, prints a ready-to-use agent API key + base URL + deposit hint. Fixed: default email must be a valid domain (@agentauth.local, not @local) or the principal can't log in (API .email() rejects dotless hosts) — added validation.
- P3 DONE (agent): packages/mcp-server — stdio MCP server (@modelcontextprotocol/sdk 1.29) exposing list_credentials + use_credential, self-contained fetch client, 8 vitest, README w/ Claude Desktop config. VERIFIED LIVE: MCP client spawned the server against the running stack and use_credential returned the real secret.
- P4 DONE (agent): SDKs publish-ready (sdk-ts npm pack dry-run clean dist-only; sdk-py builds wheel+sdist) + examples/{ts-agent,python-agent} (typecheck/import verified).
- P5 DONE (orch): end-to-end verified — docker stack + `agentauth:init` key + deposit + vault use → secret; MCP server live use_credential → secret; regression gauntlet green (server 127, mcp 8; monorepo 202 tests incl sdk-ts 30, sdk-py 26, web 11). README quickstart (one-command docker) + MCP/examples ecosystem entries added.

## Proxy mode (2026-06-15)

- PX DONE: server-side credential injection (`POST /v1/vault/credentials/:id/proxy`, scope `vault:proxy`) so the secret never reaches the agent; SDK-TS/PY + MCP clients; host-pinned, no-redirect, no plaintext-http, SSRF/metadata guard (literal incl. bracketed/IPv4-mapped IPv6 + decimal/hex/octal IPv4 encodings, AND post-DNS resolution), **connection pinned to validated IPs (node:http(s) + custom `lookup`) so DNS rebinding can't reach a private address**, body+header secret redaction, charge-after-validate (a guard-rejected proxy never burns a maxUses slot). Hardened across a 5-round adversarial verification loop (12→3→8→1→0 findings). Server tests green.
