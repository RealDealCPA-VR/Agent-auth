/**
 * AgentAuth — browser-login example (TypeScript SDK + Playwright).
 *
 * Some logins aren't an API call — they're a web app behind a cookie, a stored
 * session, or a login form. This example shows an agent driving a real browser
 * and authenticating to a target WITHOUT ever handling the raw secret in its own
 * reasoning/tool layer:
 *
 *   1. Construct an AgentAuthClient from env (AGENTAUTH_BASE_URL / AGENTAUTH_API_KEY).
 *   2. Launch a Playwright browser + page.
 *   3. Call `aa.browserLogin(page, TARGET)` — the SDK fetches the browser-login
 *      PLAN from AgentAuth, applies it to the page (sets cookies / fills the form /
 *      sets the auth header / seeds localStorage), and returns a NON-secret summary.
 *   4. Navigate as an authenticated session.
 *
 * Trust model: the plan carries secret material (same trust level as `/use`), but
 * `browserLogin` confines it to THIS process's memory — the secret flows only into
 * the browser. The return value is a non-secret summary (mode + names/counts), so
 * it is safe to log. The agent's reasoning/LLM layer never sees the secret. If you
 * need the strict "secret never reaches the agent" guarantee instead, use proxy
 * mode (see ../README.md).
 *
 * Requires the `vault:use` scope on the agent key, a credential whose target is
 * TARGET, and (for password credentials) a `metadata.browser` form spec on it.
 *
 * Run:
 *   pnpm add playwright @agentauth/sdk      # playwright is not bundled by the SDK
 *   npx playwright install chromium
 *   AGENTAUTH_API_KEY=aa_... TARGET=app.example.com pnpm tsx examples/browser-login.ts
 */

import { AgentAuthClient, AgentAuthError, ApprovalPendingError } from '@agentauth/sdk';
import { chromium } from 'playwright';

async function main(): Promise<void> {
  const baseUrl = process.env.AGENTAUTH_BASE_URL ?? 'http://localhost:8080';
  const apiKey = process.env.AGENTAUTH_API_KEY;
  const target = process.env.TARGET ?? 'app.example.com';

  if (!apiKey) {
    console.error(
      'Missing AGENTAUTH_API_KEY. Mint an agent key (scope vault:use) and export it:\n' +
        '  export AGENTAUTH_API_KEY=aa_<uuid>.<secret>\n' +
        'See examples/README.md for the full bootstrap.',
    );
    process.exitCode = 1;
    return;
  }

  const aa = new AgentAuthClient({ baseUrl, apiKey });
  console.log(`AgentAuth browser-login example → ${baseUrl}`);

  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();

    console.log(`\nLogging the browser into target "${target}"…`);
    try {
      // Fetch the plan, apply it to the page, and get back a NON-secret summary.
      // The secret material in the plan flows only into the browser — it is never
      // placed in this return value or logged.
      const summary = await aa.browserLogin(page, target);
      console.log(`  ✓ applied a "${summary.mode}" login plan (no secret left this process)`);

      // The page is now authenticated — navigate as the logged-in user.
      const home = target.startsWith('http') ? target : `https://${target}/`;
      await page.goto(home);
      console.log(`  ✓ navigated to ${page.url()} as an authenticated session`);
    } catch (err) {
      if (err instanceof ApprovalPendingError) {
        console.log(
          `  ⏳ this credential requires human approval (requestId=${err.requestId}). ` +
            'Approve it in the console, then re-run.',
        );
        return;
      }
      if (err instanceof AgentAuthError) {
        console.error(`  ✗ ${err.status} ${err.code}: ${err.message}`);
        if (err.status === 422) {
          console.error(
            '    No browser-login spec for this credential. A password credential needs an\n' +
              '    explicit metadata.browser form spec; set it at deposit time / in the admin UI.',
          );
        }
        process.exitCode = 1;
        return;
      }
      throw err;
    }
  } finally {
    await browser.close();
  }
}

main().catch((err: unknown) => {
  console.error('Unexpected error:', err);
  process.exitCode = 1;
});
