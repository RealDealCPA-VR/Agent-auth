# MFA browser-login demo

A runnable end-to-end proof that an agent can log into a web app, hit an MFA
challenge, escalate it to a human for approval, and finish — with the password and
the one-time code confined to the SDK process (never logged, never in the model's
context).

- `site/` — a static mock "IRS e-Services" site: `login.html` → `mfa.html` → `dashboard.html`.
- `demo.ts` — serves the site, deposits a form credential with an MFA spec, issues
  an agent, and drives `browserLogin` → `resolveMfa` with the SDK. The human tap is
  simulated via the API so it runs unattended; remove `approveAsHuman(...)` to
  approve live from the admin UI (`/mfa`) instead.

See [`docs/demo-irs-transcript.md`](../../docs/demo-irs-transcript.md) for the
90-second shot list and run instructions.

```bash
# server running (pnpm dev), then:
pnpm add -D playwright tsx && npx playwright install chromium
npx tsx examples/mfa-demo/demo.ts
```
