"""AgentAuth — Python agent example.

What this does (the whole agent loop):
  1. Construct an AgentAuthClient from env (AGENTAUTH_BASE_URL / AGENTAUTH_API_KEY).
  2. List the credentials this agent is scoped to see (metadata only — no secrets).
  3. Use one credential *by target* (env TARGET, default "github.com").
  4. Print a REDACTED confirmation. The raw secret is NEVER printed in full —
     only its type, length, and a short prefix, so you can confirm it worked.

Run:  AGENTAUTH_API_KEY=aa_... python main.py
See ../README.md for how to boot the server and mint an agent key.
"""

from __future__ import annotations

import os
import sys

from agentauth import AgentAuthClient, AgentAuthError, ApprovalPendingError


def redact(secret: str) -> str:
    """Show a secret without leaking it: length + a tiny prefix only."""
    return f'<redacted {len(secret)} chars, starts "{secret[:4]}…">'


def main() -> int:
    base_url = os.environ.get("AGENTAUTH_BASE_URL", "http://localhost:8080")
    api_key = os.environ.get("AGENTAUTH_API_KEY")
    target = os.environ.get("TARGET", "github.com")

    if not api_key:
        print(
            "Missing AGENTAUTH_API_KEY. Mint an agent key and export it:\n"
            "  export AGENTAUTH_API_KEY=aa_<uuid>.<secret>\n"
            "See examples/README.md for the full bootstrap.",
            file=sys.stderr,
        )
        return 1

    print(f"AgentAuth agent example → {base_url}")
    with AgentAuthClient(base_url, api_key) as client:
        # 1) Discover what this agent can see (never any secrets here).
        page = client.list_credentials(limit=200)
        items = page["items"]
        print(f"\nVisible credentials ({page['pagination']['total']} total):")
        if not items:
            print("  (none — deposit a credential and scope the agent to it)")
        for c in items:
            print(f"  • {c['target']}  [{c['type']}]  {c['label']}")

        # 2) Use one by target. The SDK resolves target -> id, then unseals it.
        print(f'\nUsing credential for target "{target}"…')
        try:
            used = client.use_credential(target)
        except ApprovalPendingError as err:
            print(
                f"  ⏳ this credential requires human approval "
                f"(requestId={err.request_id}). Approve it, then re-run."
            )
            return 0
        except AgentAuthError as err:
            print(f"  ✗ {err.status} {err.code}: {err.message}", file=sys.stderr)
            if err.status == 404:
                print(
                    f'    No credential for target "{target}". '
                    "Set TARGET=<host> to one listed above.",
                    file=sys.stderr,
                )
            return 1

        print("  ✓ got a sealed secret, unsealed for this instant:")
        print(f"    target:  {used['target']}")
        print(f"    type:    {used['type']}")
        print(f"    secret:  {redact(used['secret'])}")
        # In a real agent you'd hand `used['secret']` straight to the downstream
        # call (HTTP header, login form, etc.) and never persist or log it.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
