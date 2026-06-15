# @agentauth/mcp-server

**An MCP server that hands your AgentAuth vault to any MCP-capable agent — with zero code.**

This package is a [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
stdio server. Point it at your [AgentAuth](../../README.md) instance and an agent
key, drop it into an MCP host (Claude Desktop, or any MCP client), and the agent
gains three tools:

| Tool               | Input                  | Returns                                                                 |
| ------------------ | ---------------------- | ----------------------------------------------------------------------- |
| `list_credentials` | _(none)_               | The vault listing **metadata** as JSON — `id, target, label, type, metadata, expiresAt`. **No secrets.** |
| `use_credential`   | `{ idOrTarget: string }` | The unsealed credential **including the live `secret`**, fully audited server-side. |
| `proxy_request`    | `{ idOrTarget: string, method?, path?, query?, headers?, body? }` | The downstream `{ status, headers, body }` — AgentAuth makes the request with the credential injected server-side; **the secret is never exposed to the agent**. |

The agent discovers what it's scoped for with `list_credentials`, then either
unseals exactly one secret for use with `use_credential` — identified by
credential UUID **or** by target (e.g. `github.com`, resolved against the
listing) — or, better, calls the target through `proxy_request` so the secret
never leaves AgentAuth at all. The secret is revealed (or injected) only for the
instant it's used, and every use is recorded in AgentAuth's tamper-evident audit
log.

> **Prefer `proxy_request` when you only need to *call* the target.** AgentAuth
> makes the downstream request server-side with the credential injected (the host
> is pinned to the credential's target — you control only method/path/query/
> headers/body) and returns the downstream `{ status, headers, body }` with the
> secret redacted. The raw secret never enters the agent's context. Reach for
> `use_credential` only when you genuinely need the raw secret value itself.

> **`use_credential` returns a live secret.** Its tool description tells the model
> to use the secret to authenticate and never log, store, or echo it. Scope your
> agent key narrowly (specific `target:` globs) so the bridge can only ever reach
> the credentials you intend.

## Configuration

The server reads two environment variables:

| Variable             | Required | Default                 | Description                                   |
| -------------------- | -------- | ----------------------- | --------------------------------------------- |
| `AGENTAUTH_API_KEY`  | **yes**  | —                       | Your agent API key, `aa_<uuid>.<secret>` (shown once at agent creation). |
| `AGENTAUTH_BASE_URL` | no       | `http://localhost:8080` | Base URL of your AgentAuth API.               |

If `AGENTAUTH_API_KEY` is missing the server prints a clear message to stderr and
exits — there's no point bridging a vault it can't reach.

## Use it with Claude Desktop (or any MCP client)

Add an entry to your MCP client's server config. For **Claude Desktop**, edit
`claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`, Windows:
`%APPDATA%\Claude\claude_desktop_config.json`):

```jsonc
{
  "mcpServers": {
    "agentauth": {
      "command": "npx",
      "args": ["-y", "@agentauth/mcp-server"],
      "env": {
        "AGENTAUTH_API_KEY": "aa_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.your-secret",
        "AGENTAUTH_BASE_URL": "http://localhost:8080"
      }
    }
  }
}
```

Prefer a pinned local install? Build this package (`pnpm build`) and point at the
bin directly:

```jsonc
{
  "mcpServers": {
    "agentauth": {
      "command": "node",
      "args": ["/absolute/path/to/packages/mcp-server/dist/index.js"],
      "env": {
        "AGENTAUTH_API_KEY": "aa_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.your-secret",
        "AGENTAUTH_BASE_URL": "http://localhost:8080"
      }
    }
  }
}
```

Restart the client. The agent now has the `list_credentials`, `use_credential`,
and `proxy_request` tools available — no application code required.

## How it behaves

- **`list_credentials`** pages the vault at the max size (200) and returns the
  metadata page verbatim as JSON text. Secrets are never present in this response.
- **`use_credential`** sends a UUID straight to `POST /v1/vault/credentials/:id/use`;
  for any other string it lists, matches `items[].target`, and uses the first
  match. The returned text is the unsealed credential JSON, including `secret`.
- **`proxy_request`** resolves the id the same way (UUID direct, else by target)
  and `POST`s to `/v1/vault/credentials/:id/proxy` with `{ method, path, query?,
  headers?, body? }`. AgentAuth performs the downstream request itself with the
  credential injected and returns `{ status, headers, body }` (secret redacted) —
  requires the agent key to hold the **`vault:proxy`** scope.
- **Errors** are mapped to readable tool errors with the AgentAuth status + code
  and an actionable hint: `401` (bad key), `403` (scope/target denied), `404`
  (no such credential), `410` (expired / outside window), `429` (rate / use-limit),
  `503` (vault fail-closed), plus network-unreachable.
- **Human approval:** if a credential's policy requires approval, the server
  returns `202` and the tool replies with a clear "awaiting human approval"
  message (including the request id) instead of a secret. Approve it in AgentAuth,
  then call the tool again.

## Develop

```bash
pnpm install
pnpm typecheck   # strict TS (NodeNext ESM)
pnpm test        # vitest — fetch is stubbed, no network/DB
pnpm build       # emit dist/ (the runnable bin)
```

The HTTP client (`src/client.ts`) is self-contained — it depends only on the
global `fetch`, not on the other AgentAuth SDK packages.

## License

MIT.
