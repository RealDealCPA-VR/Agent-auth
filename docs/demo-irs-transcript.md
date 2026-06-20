# Demo — "Pull the IRS transcript" (browser login + human-approved MFA)

A 90-second proof of the thesis: an agent logs into a real web app, hits MFA, a
human approves from their phone, the code is injected into the browser, the task
completes — and **the password and the MFA code never appear in any log or in the
model's context.**

> The flow is the point, not the site. This demo ships a **mock** IRS e-Services
> site (`examples/mfa-demo/site/`) so it runs anywhere. Swap in a real account
> once you've watched it work — but read the **"Hardened on every layer"**
> section of the README first, and never point it at a real client account
> before that.

## What the audience sees (90s, no narration needed)

| t | Shot |
| --- | --- |
| 0:00 | Claude Desktop with the AgentAuth MCP server configured. Prompt: **"Pull the IRS transcript for Riverside Dental."** |
| 0:05 | The agent calls the vault; a browser opens and fills the login form (you never see the password — AgentAuth typed it). |
| 0:12 | The browser lands on the **MFA page**. The agent reports: *"I need an MFA code — sent to your authenticator app."* (the non-secret `promptText`). |
| 0:18 | **Your phone buzzes** — an AgentAuth approval: *"IRS e-Services MFA requested by agent firm-bot · authenticator app."* (or the admin UI `/mfa` card). |
| 0:25 | You approve (enter the code / tap "I approved the push"). |
| 0:30 | The code is injected into the browser, the session continues, the transcript page loads. |
| 0:40 | Cut to the **AgentAuth audit trail** — `credential.browser` → `mfa.requested` → `mfa.approved` (by you) → `mfa.consumed`. Timestamps. **No password, no code anywhere in the log.** |
| 0:55 | Claude: *"Transcript pulled for Riverside Dental, saved to their work item."* |

## Run the proof yourself (headless, end-to-end)

`examples/mfa-demo/demo.ts` runs the entire flow with a real browser and the
official SDK, simulating the human tap via the API so it completes unattended:

```bash
# 1. start the AgentAuth server
pnpm db:up && pnpm db:migrate && pnpm dev          # → http://localhost:8080

# 2. in another shell, from the repo root:
pnpm add -D playwright tsx
npx playwright install chromium
npx tsx examples/mfa-demo/demo.ts
```

Expected output (note: a non-secret summary — **no `demo-password`, no `123456`**):

```
browserLogin → {"mode":"form","target":"localhost","url":"http://localhost:8799/login.html","authenticated":false,"filledFields":2,"submitted":false,"mfa":{"kind":"totp","promptText":"authenticator app","detectedAt":"...","challengeId":"...","inputSelector":"#otp","submitSelector":"#verify","allowedDomains":["localhost"]}}
MFA challenge: authenticator app
MFA resolved → {"resolved":true,"status":"approved","by":"mfa-demo+...@example.com","at":"..."}
final page: http://localhost:8799/dashboard.html
```

> `promptText` here is the credential's `channelHint` ("authenticator app"). Omit
> `channelHint` from the `mfa` spec to fall through to the page's visible text
> ("Enter the 6-digit code …") instead.

To do it as a **live, human-in-the-loop** demo instead of the simulated approval:
remove the `approveAsHuman(...)` call from `demo.ts`, open the admin UI at
`/mfa` (or wire the MCP server into Claude Desktop), and approve the request there
while `resolveMfa` polls.

## Recording the clip

Recording the screen is a manual step (it can't be automated here). Capture the
three windows in one frame — Claude Desktop, the browser, and the AgentAuth audit
trail — run the flow, and trim to ~90s. Drop the file at
`docs/media/demo-irs-transcript.mp4` (or a GIF) and it will render from the README
link at the top of the repo. **Note:** `docs/media/` does not exist until you add
the recording, so the README's video link is a placeholder until then.

## Why it's safe (the part to say out loud)

- The agent's reasoning/LLM layer only ever sees a **non-secret summary** and the
  MFA `promptText`. The password is typed by the SDK; the code is injected into the
  DOM by the SDK. Neither is returned to the model or written to the audit log.
- The MFA approval is **owner-only** (or a configured `delegateApproverId`),
  single-use, and TTL-bounded; revoking the agent cancels pending requests
  instantly. Every step is on the tamper-evident HMAC audit chain.
