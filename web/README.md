# AgentAuth — Admin Web UI

A lightweight Next.js 15 (App Router, TypeScript) admin console for the
[AgentAuth](../README.md) credential-vault API. It is the human-facing surface:
register / sign in, open passports, deposit credentials, mint and revoke scoped
agent keys, and inspect the tamper-evident audit log.

The UI is intentionally minimal — no UI component library, plain CSS, and a
single typed `fetch`-based API client. It talks to the API entirely from the
browser using the human **session JWT** (stored in `localStorage`). Agent API
keys (`aa_<uuid>.<secret>`) are shown exactly once at issue time and are never
persisted by this app.

## Stack

- Next.js 15 (App Router) + React 19 + TypeScript (strict)
- No CSS framework — `app/globals.css` (dark crimson/black theme)
- Vitest + jsdom for the API-client unit tests

## Getting started

```bash
cp .env.example .env.local        # set NEXT_PUBLIC_API_URL if not localhost:8080
pnpm install
pnpm dev                          # http://localhost:3000
```

The API must be running and reachable at `NEXT_PUBLIC_API_URL` (default
`http://localhost:8080`). CORS on the API must allow this origin.

## Configuration

| Variable              | Default                 | Notes                                  |
| --------------------- | ----------------------- | -------------------------------------- |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | API base origin. Public, no secrets.   |

## Scripts

```bash
pnpm dev         # dev server on :3000
pnpm build       # production build
pnpm start       # serve the production build
pnpm typecheck   # tsc --noEmit (strict)
pnpm lint        # next lint
pnpm test        # vitest run (api-client unit tests)
```

## Pages

| Route             | Purpose                                                        |
| ----------------- | ------------------------------------------------------------- |
| `/login`          | Register and/or sign in; stores the session token.            |
| `/passports`      | List and create passports.                                    |
| `/passports/[id]` | Deposit a credential and list a passport's credentials.       |
| `/agents`         | Issue an agent (shows the API key once), list, and revoke.    |
| `/approvals`      | Review and approve/deny pending credential-use requests.      |
| `/audit`          | Browse the audit log and verify hash-chain integrity.         |

## Architecture

```
web/
  app/
    layout.tsx          shell + top nav
    page.tsx            redirect: /passports or /login
    globals.css         dark crimson/black theme
    components/
      Nav.tsx           auth-aware top navigation + logout
      RequireAuth.tsx   client-side route guard (redirects to /login)
      ErrorBanner.tsx   renders the API error envelope consistently
    login/page.tsx
    passports/page.tsx
    passports/[id]/page.tsx
    passports/[id]/OAuthConnect.tsx   connect an OAuth credential
    agents/page.tsx
    approvals/page.tsx
    audit/page.tsx
  lib/
    api.ts              typed API client + token storage + error mapping
    api.test.ts         unit tests (mocked fetch + jsdom localStorage)
```

## Notes & decisions

- **Auth is client-side only.** The session token lives in `localStorage`, so
  route protection is enforced in the browser via `RequireAuth`. There is no
  server-side session; this is an admin tool, not a public site.
- **Agent keys are never stored.** The issue response's `apiKey` is rendered in
  a one-time reveal box with a copy button and is dropped from state on dismiss.
- **Audit payloads are open-ended.** The audit table derives the actor from
  `principalId`/`agentId`, the target from `detail.target`/`credentialId`, and the
  time from `createdAt`/`timestamp`/`at`, tolerating shape variation so it keeps
  working as the audit schema evolves.
