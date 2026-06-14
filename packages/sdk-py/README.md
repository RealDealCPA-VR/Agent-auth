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

# Use a credential by id...
cred = client.use_credential("cred_123")

# ...or by target host — resolved against the credentials this agent can see.
cred = client.use_credential("github.com")
token = cred["secret"]            # unsealed for this instant, fully audited

# Discover what's available (metadata only, never secrets):
for c in client.list_credentials()["items"]:
    print(c["target"], c["label"], c["type"])
```

`use_credential(id_or_target)` first tries the value as a credential **id**; on a
`404` it falls back to treating it as a **target** and resolves it client-side by
paging the agent's visible credentials (the data plane has no server-side target
lookup). A non-404 error (e.g. `403 forbidden`) is raised as-is — no fallback.

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
client.verify_audit()              # {ok, count, brokenAtSeq}
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
`list_passports`, `deposit_credential`, `list_credentials`, `issue_agent`,
`list_agents`, `revoke_agent`, `list_audit`, `verify_audit`.

**`AgentAuthClient`** — `list_credentials`, `use_credential(id_or_target)`.

## Development

```bash
pip install -e ".[test]"
pytest                 # all HTTP is mocked via httpx.MockTransport — no network
```

MIT licensed. See the [root README](../../README.md) and `SECURITY.md` for the
security model.
