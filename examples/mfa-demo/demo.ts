/**
 * End-to-end MFA browser-login demo (the proof behind docs/demo-irs-transcript.md).
 *
 * It serves the mock IRS e-Services site in ./site, deposits a form credential
 * with an MFA spec, issues an agent, and drives the full flow with the official
 * SDK:
 *
 *   browserLogin(page, target)  →  lands on the MFA page  →  resolveMfa(...)
 *        → human approves (here: simulated via the API; in the real demo a person
 *          taps "approve" on their phone / the admin UI at /mfa)
 *        → the one-time code is injected into the DOM → transcript downloads.
 *
 * The password and the MFA code NEVER leave the SDK process — only a non-secret
 * summary is logged. Run the AgentAuth server first (pnpm dev), then:
 *
 *   pnpm add -D playwright tsx && npx playwright install chromium
 *   npx tsx examples/mfa-demo/demo.ts
 *
 * The AgentAuth SDK is imported directly from source (tsx transpiles it; the SDK
 * has zero runtime dependencies), so no extra install or workspace wiring is
 * needed. In your own app you'd `import { ... } from '@agentauth/sdk'` instead.
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { chromium } from 'playwright';
import { HumanClient, AgentAuthClient } from '../../packages/sdk-ts/src/index.ts';

const API = process.env.AGENTAUTH_BASE_URL ?? 'http://localhost:8080';
const PORT = Number(process.env.DEMO_PORT ?? 8799);
const HOST = 'localhost';
const TARGET = `${HOST}:${PORT}`;
const SITE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'site');
const PASSWORD = 'correct-horse-battery-staple';

/** Serve the static mock site so the browser has a real origin to log in to. */
function serveSite(): http.Server {
  const types: Record<string, string> = { '.html': 'text/html; charset=utf-8' };
  const server = http.createServer(async (req, res) => {
    const name = (req.url === '/' || !req.url ? '/login.html' : req.url).split('?')[0]!;
    try {
      const body = await readFile(path.join(SITE, path.basename(name)));
      res.writeHead(200, { 'content-type': types[path.extname(name)] ?? 'text/plain' });
      res.end(body);
    } catch {
      res.writeHead(404).end('not found');
    }
  });
  server.listen(PORT);
  return server;
}

/** Simulate the human approver: poll the owner's MFA queue and approve THE request
 * matching `challengeId` with a code. In the real demo this is a person tapping
 * "approve" on their phone (the /mfa UI). */
async function approveAsHuman(token: string, challengeId: string, code: string): Promise<void> {
  for (let i = 0; i < 60; i += 1) {
    const res = await fetch(`${API}/v1/mfa`, { headers: { authorization: `Bearer ${token}` } });
    const items =
      ((await res.json()) as { items?: Array<{ id: string; challengeId: string }> }).items ?? [];
    // Match our own challenge — don't blindly approve items[0] (a stale/other row).
    const mine = items.find((m) => m.challengeId === challengeId);
    if (mine) {
      await fetch(`${API}/v1/mfa/${mine.id}/approve`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      return;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('no pending MFA request appeared');
}

async function main(): Promise<void> {
  const server = serveSite();

  // --- Human (one-time setup): deposit the credential + issue the agent. -------
  const email = `mfa-demo+${Date.now()}@example.com`;
  await HumanClient.register(API, email, PASSWORD);
  // One login serves both roles: build the client from the raw session token and
  // reuse that same token for the approver simulation (no redundant second login).
  const session = await HumanClient.loginRaw(API, email, PASSWORD);
  const human = new HumanClient({ baseUrl: API, token: session.token });
  const passport = await human.createPassport('demo');
  await human.depositCredential(passport.id, {
    target: TARGET,
    label: 'IRS e-Services',
    type: 'password',
    secret: 'demo-password',
    metadata: {
      username: 'demo-user',
      browser: {
        mode: 'form',
        url: `http://${TARGET}/login.html`,
        fields: [
          { selector: '#username', valueFrom: 'username' },
          { selector: '#password', valueFrom: 'secret' },
        ],
        submitSelector: '#submit',
        successUrlIncludes: 'dashboard',
        mfa: { kind: 'totp', channelHint: 'authenticator app', inputSelector: '#otp', submitSelector: '#verify' },
        allowedDomains: [HOST],
      },
    },
  });
  const agent = await human.issueAgent({
    passportId: passport.id,
    name: 'firm-bot',
    scopes: ['vault:read', 'vault:use', `target:${HOST}`],
  });

  // --- Agent: log in via the browser, hit MFA, resolve it. ---------------------
  const aa = new AgentAuthClient({ baseUrl: API, apiKey: agent.apiKey });
  const browser = await chromium.launch();
  const context = await browser.newContext(); // fresh ephemeral context (no SSO bleed)
  const page = await context.newPage();

  const summary = await aa.browserLogin(page, TARGET);
  console.log('browserLogin →', JSON.stringify(summary)); // non-secret; no password

  if (summary.mfa) {
    console.log('MFA challenge:', summary.mfa.promptText);
    // Kick off resolution (opens the request + polls); approve concurrently.
    const resolving = aa.resolveMfa(page, TARGET, summary.mfa, {
      inputSelector: '#otp',
      submitSelector: '#verify',
      pollIntervalMs: 500,
    });
    await approveAsHuman(session.token, summary.mfa.challengeId, '123456');
    const r = await resolving;
    console.log('MFA resolved →', JSON.stringify(r)); // non-secret; no code
    // The mock advances via a synchronous client-side `location.href='dashboard.html'`,
    // which `networkidle` (resolveMfa's settle) may not have committed yet. Wait for the
    // target URL explicitly so the assertion below isn't a navigation race / flake.
    await page.waitForURL('**/dashboard.html').catch(() => {});
    // Fail loudly if the code was not actually applied / the flow didn't complete.
    if (!r.resolved || !page.url().includes('dashboard')) {
      throw new Error(`MFA flow did not complete: ${JSON.stringify(r)} url=${page.url()}`);
    }
  }

  console.log('final page:', page.url()); // .../dashboard.html → transcript available

  await context.close();
  await browser.close();
  server.close();
}

main().catch((err) => {
  console.error('demo failed:', err);
  process.exit(1);
});
