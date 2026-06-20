'use client';

import { useEffect } from 'react';

/**
 * Defensive OAuth callback page for deployments that point the provider redirect
 * at the web app (rather than the API's own callback page). It posts the same
 * non-secret signal the API success page does, so the opener (the passport
 * detail view) refreshes its credential list, then closes itself.
 *
 * No secret is ever read or carried here — the server has already sealed the
 * captured credential into the vault by the time this loads.
 */
const OAUTH_CAPTURED = 'agentauth:oauth-captured';

export default function OAuthCallbackPage() {
  useEffect(() => {
    try {
      window.opener?.postMessage({ type: OAUTH_CAPTURED }, '*');
    } catch {
      /* opener gone or cross-origin restricted — nothing to do */
    }
  }, []);

  return (
    <main style={{ padding: '2rem', maxWidth: 480, margin: '0 auto' }}>
      <h1>Authorization complete</h1>
      <p className="muted">
        The credential has been captured and sealed into the vault. You can
        close this tab and return to AgentAuth — the credential list will
        refresh automatically.
      </p>
    </main>
  );
}
