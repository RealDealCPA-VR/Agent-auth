# AgentAuth — runnable examples

Two minimal, end-to-end agent examples — one in **TypeScript**, one in
**Python** — that do the same thing through the AgentAuth SDKs:

1. construct an agent client from environment variables,
2. list the credentials the agent is scoped to see (metadata only — no secrets),
3. **use** one credential by its `target` (resolving target → id under the hood),
4. print a **redacted** confirmation — the raw secret is never printed in full.

| Example                              | SDK                                       |
| ------------------------------------ | ----------------------------------------- |
| [`ts-agent/`](./ts-agent)            | [`@agentauth/sdk`](../packages/sdk-ts)    |
| [`python-agent/`](./python-agent)    | [`agentauth`](../packages/sdk-py)         |

Both depend on the **local** SDK packages in this monorepo (via `file:` /
editable install), so you can run them against your own checkout without
publishing anything.

---

## Prerequisites

### 1. Run the AgentAuth server

From the repo root (needs Docker for Postgres — see the root
[README](../README.md) Quickstart):

```bash
pnpm install
pnpm db:up                       # Postgres in Docker (port 5433)
cp .env.example .env
node -e "console.log('MASTER_KEY='+require('crypto').randomBytes(32).toString('base64'))" >> .env
node -e "console.log('JWT_SECRET='+require('crypto').randomBytes(32).toString('base64'))" >> .env
pnpm db:generate && pnpm db:migrate
pnpm dev                         # http://localhost:8080
```

### 2. Bootstrap an agent key

The examples authenticate as an **agent**, so you need an agent API key
(`aa_<uuid>.<secret>`). Mint one with the human-side flow (curl shown; the SDKs'
`HumanClient` does the same). Set `BASE` to your server:

```bash
BASE=http://localhost:8080

# Register + log in (once)
curl -s $BASE/v1/principals -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery"}'
TOKEN=$(curl -s $BASE/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"correct-horse-battery"}' | jq -r .token)

# Open a passport and deposit a credential for github.com
PASSPORT=$(curl -s $BASE/v1/passports -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"work"}' | jq -r .id)
curl -s $BASE/v1/passports/$PASSPORT/credentials -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"target":"github.com","label":"GH token","type":"api_key","secret":"ghp_example_secret"}'

# Mint a scoped agent key — printed exactly once
curl -s $BASE/v1/agents -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"passportId\":\"$PASSPORT\",\"name\":\"example-agent\",\"scopes\":[\"vault:read\",\"vault:use\",\"target:github.com\"]}" \
  | jq -r .apiKey
```

Copy the printed `aa_…` value — that's your `AGENTAUTH_API_KEY`.

### 3. Environment variables (both examples)

| Variable             | Default                 | Meaning                                    |
| -------------------- | ----------------------- | ------------------------------------------ |
| `AGENTAUTH_BASE_URL` | `http://localhost:8080` | AgentAuth API base URL                     |
| `AGENTAUTH_API_KEY`  | _(required)_            | the agent key `aa_<uuid>.<secret>`         |
| `TARGET`             | `github.com`            | which credential target to use             |

```bash
export AGENTAUTH_BASE_URL=http://localhost:8080
export AGENTAUTH_API_KEY=aa_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.secret
export TARGET=github.com
```

---

## Run the TypeScript example

```bash
cd examples/ts-agent
pnpm install        # links @agentauth/sdk from ../../packages/sdk-ts
                    # (build the SDK first: cd ../../packages/sdk-ts && pnpm build)
pnpm build          # compile this example
pnpm start          # runs the agent loop

# type-only check, no server needed:
pnpm exec tsc --noEmit
```

Expected output (redacted secret):

```
AgentAuth agent example → http://localhost:8080

Visible credentials (1 total):
  • github.com  [api_key]  GH token

Using credential for target "github.com"…
  ✓ got a sealed secret, unsealed for this instant:
    target:  github.com
    type:    api_key
    secret:  <redacted 17 chars, starts "ghp_…">
```

## Run the Python example

```bash
cd examples/python-agent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # editable-installs ../../packages/sdk-py
python main.py
```

Same redacted output as above. The Python SDK requires Python 3.9+ and `httpx`
(pulled in automatically).

---

## Notes

- **Secrets are never printed in full.** Both examples redact to `length + 4-char
  prefix`. Treat `used.secret` / `used['secret']` as write-once: hand it to the
  downstream call and never log or persist it.
- If a credential's policy **requires human approval**, `useCredential` raises
  `ApprovalPendingError` (HTTP 202). Approve it in the admin console / via the
  approvals API, then re-run.
- No credential for your `TARGET`? You'll get a `404 not_found`. Pick a target
  from the listing the example prints, or deposit + scope one.
