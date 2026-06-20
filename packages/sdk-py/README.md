# agentauth (Python SDK)

Official Python client for [**AgentAuth**](../../README.md) — the credential
vault and identity broker for AI agents. Your agent presents its own key and
gets exactly the access you granted: scoped, time-boxed, revocable, audited —
and the raw secret is unsealed only for the instant it's used.

```bash
pip install agentauth
```

Requires Python 3.9+ and [`httpx`](https://www.python-httpx.org/).

## Two clients, two planes

The API has two authentication surfaces, so the SDK has two clients:

| Client             | Auth                         | Use for |
| ------------------ | ---------------------------- | ------- |
| `HumanClient`      | session JWT (Bearer)         | register, passports, deposit, agents, audit |
| `AgentAuthClient`  | agent API key `aa_<uuid>.<secret>` | discover + use credentials at runtime |

## The agent side (the one-liner)

This is what your agent runs. Give it a key, ask for a target, get the secret.

```python
from agentauth import AgentAuthClient

client = AgentAuthClient("https://api.agentauth.dev", "aa_uuid.secret")

# Use a credential by id (a UUID)...
cred = client.use_credential("22222222-2222-4222-8222-222222222222")

# ...or by target host — resolved against the credentials this agent can see.
cred = client.use_credential("github.com")
token = cred["secret"]            # unsealed for this instant, fully audited

# Discover what's available (metadata only, never secrets):
for c in client.list_credentials()["items"]:
    print(c["target"], c["label"], c["type"])
```

`use_credential(id_or_target)`: if the value is a **UUID** it is POSTed straight
to the use endpoint as a credential **id**. Otherwise it is treated as a
**target** (e.g. `github.com`) and resolved client-side by paging the agent's
visible credentials — the first whose target matches wins, and a local `404
not_found` is raised if none match. The data plane has no server-side target
lookup, so a target string is never POSTed to the uuid-typed `:id` route.
Server-side errors from an id-based use (`403`, `410`, …) are raised as-is.

## Proxy mode (the secret never leaves the vault)

Even better than receiving the unsealed secret: don't receive it at all. With
`proxy()`, AgentAuth makes the downstream request **server-side** against the
credential's pinned target and injects the secret for you — the raw secret never
appears in the response. The agent only controls the method, path, query,
headers, and body; the host is fixed to the credential's target.

```python
from agentauth import AgentAuthClient

client = AgentAuthClient("https://api.agentauth.dev", "aa_uuid.secret")

# By id or by target — resolved exactly like use_credential().
res = client.proxy(
    "github.com",
    method="POST",
    path="/repos/me/app/issues",          # must start with "/"
    query={"per_page": "1"},               # optional
    headers={"accept": "application/vnd.github+json"},  # optional
    body='{"title":"filed by my agent"}',  # optional
)
print(res["status"])    # downstream status, e.g. 201
print(res["headers"])   # downstream response headers (secret redacted)
print(res["body"])      # downstream response body (secret redacted)
```

The agent key needs the **`vault:proxy`** scope. Proxy errors follow the same
`AgentAuthError` contract: `403` (missing `vault:proxy` / forbidden target),
`400` (invalid path), `410` (expired/window), `429` (use-limit reached), `502`
(upstream / OAuth refresh failed), `504` (timeout). A `202` (approval required)
raises `ApprovalPendingError`.

How the secret is injected is set at **deposit** time via the optional
`injection` argument:

```python
client.deposit_credential(
    passport["id"], target="api.example.com", label="X", type="api_key",
    secret="sk_live_...",
    injection={"mode": "header", "name": "X-Api-Key", "prefix": "Token "},
    # also: {"mode": "bearer"} | {"mode": "basic"} | {"mode": "cookie"}
    #       | {"mode": "query", "name": "api_key"}
)
```

Defaults to `bearer` (or `cookie` for `type="cookie"`) when omitted.

## The human side (management)

```python
from agentauth import HumanClient

client = HumanClient("https://api.agentauth.dev")
client.register("me@example.com", "correct-horse-battery")  # optional
client.login("me@example.com", "correct-horse-battery")     # stores the token

passport = client.create_passport("work")

client.deposit_credential(
    passport["id"],
    target="github.com",
    label="GH token",
    type="api_key",                # password | oauth_token | cookie | api_key
    secret="ghp_xxx",
    metadata={"env": "prod"},      # optional
    expires_at="2031-01-01T00:00:00Z",  # optional ISO-8601
)

agent = client.issue_agent(
    passport_id=passport["id"],
    name="ci-bot",
    scopes=["vault:read", "vault:use", "target:github.com"],
)
print(agent["apiKey"])             # shown exactly once — capture it now

# Later: changed your mind? Revocation is instant and fail-closed.
client.revoke_agent(agent["id"])

# Audit
client.list_audit(limit=50)
client.verify_audit()              # {ok} (integrity boolean only)
```

`login()` stores the token on the client and sets the `Authorization` header for
you; you can also pass a token up front with `HumanClient(base_url, token=...)`.

## Errors

Every non-2xx response is raised as `AgentAuthError` with structured fields that
mirror the server's error envelope:

```python
from agentauth import AgentAuthError

try:
    client.use_credential("github.com")
except AgentAuthError as e:
    print(e.status)       # 401 / 403 / 404 / 410 / 429 / 503 / ...
    print(e.code)         # machine-readable code, e.g. "forbidden"
    print(e.message)      # human-readable message
    print(e.request_id)   # correlate with server logs / audit
    print(e.details)      # optional structured details (validation, etc.)
```

Transport-level failures (DNS, connection refused, timeout) are wrapped in the
same exception with `status == 0` and `code == "network_error"`, so callers have
exactly one thing to catch.

## Resource management

Both clients hold an `httpx` connection pool. Use them as context managers, or
call `.close()` when done:

```python
with AgentAuthClient(base_url, api_key) as client:
    client.use_credential("github.com")
```

## Method reference

**`HumanClient`** — `register`, `login`, `logout`, `create_passport`,
`list_passports`, `deposit_credential(... , *, max_uses, allowed_from,
allowed_until, require_approval)`, `list_credentials`, `issue_agent`,
`list_agents`, `revoke_agent`, `bind_agent_mtls(agent_id, *, cert_pem,
fingerprint)`, `start_oauth(passport_id, provider, *, target, label)`,
`list_audit`, `verify_audit`, `list_approvals`, `approve_request(request_id)`,
`deny_request(request_id)`.

**`AgentAuthClient`** — `list_credentials`, `use_credential(id_or_target)`,
`proxy(id_or_target, *, method, path, query, headers, body)`,
`get_browser_login_plan(id_or_target)`,
`browser_login(page, id_or_target)`.

### Browser-login (drive a real browser into a logged-in session)

For sites that can't be used via a token alone, `browser_login()` fetches a
server-issued **plan** (cookies / headers / localStorage / a form-fill script —
all carrying secret material, same trust level as `use_credential`) and applies
it to a Playwright **sync** `page`. It returns a **non-secret summary** (modes,
names, counts) — never any cookie/header/storage/form value.

```python
from playwright.sync_api import sync_playwright
from agentauth import AgentAuthClient

client = AgentAuthClient("https://api.agentauth.dev", "aa_uuid.secret")

with sync_playwright() as p:
    page = p.chromium.launch().new_page()
    summary = client.browser_login(page, "github.com")
    # summary -> {"mode": "cookie", "target": "github.com", "url": ..., "cookie_names": [...]}
    # the page is now logged in; drive it as usual.

# LIABILITY PATH — returns the secret in plaintext to your process.
# Treat it like a decrypted password: do not log, pass to an LLM, or persist it.
plan = client.get_browser_login_plan("github.com")
```

`browser_login` is the **safe path** and needs only **`vault:use`**. A `202`
(approval required) raises `ApprovalPendingError`. Playwright is **not** a
dependency of the SDK — the `page` is duck-typed.

> **`get_browser_login_plan` is the liability path.** It requires the
> **`vault:browser:raw`** scope (off by default) in addition to `vault:use`;
> without it the call is `403 missing_scope`. Prefer `browser_login`, which applies
> the plan to a page and never returns the secret to you.

### Management extras (mTLS + OAuth + approvals)

```python
# Bind an mTLS client cert to an agent (PEM or precomputed fingerprint):
client.bind_agent_mtls(agent["id"], cert_pem=open("client.crt").read())
# -> {"id": ..., "certFingerprint": "..."}

# Start an OAuth authorization-code flow; send the human's browser to authorizeUrl:
flow = client.start_oauth(passport["id"], "github", target="github.com")
print(flow["authorizeUrl"], flow["state"])

# Approvals queue (when a credential requires human approval):
for req in client.list_approvals()["items"]:
    client.approve_request(req["id"])   # or client.deny_request(req["id"])

# Deposit-time usage policy:
client.deposit_credential(
    passport["id"], target="api.example.com", label="X", type="api_key",
    secret="sk_...",
    max_uses=100,                          # cap total uses
    allowed_from="2030-01-01T00:00:00Z",   # ISO-8601 window
    allowed_until="2031-01-01T00:00:00Z",
    require_approval=True,                  # each use needs human approval
)
```

## Development

```bash
pip install -e ".[test]"
pytest                 # all HTTP is mocked via httpx.MockTransport — no network
```

MIT licensed. See the [root README](../../README.md) and `SECURITY.md` for the
security model.
