'use client';

import { useEffect, useRef, useState, FormEvent } from 'react';
import { api } from '@/lib/api';
import ErrorBanner from '../../components/ErrorBanner';

/** Message the server's OAuth callback success page posts back to the opener. */
const OAUTH_CAPTURED = 'agentauth:oauth-captured';

/**
 * "Connect an OAuth provider" form. Starts the provider authorization flow for
 * this passport and opens the returned authorizeUrl in a new tab so the user
 * can complete consent. Once authorized, the server deposits the captured
 * credential and its callback success page posts a window message back here, at
 * which point we invoke onCaptured so the parent reloads its credential list.
 * As a fallback (e.g. cross-origin opener message blocked) we briefly poll the
 * parent's reload after the consent tab opens.
 */
export default function OAuthConnect({
  passportId,
  onCaptured,
}: {
  passportId: string;
  onCaptured?: () => void;
}) {
  const [provider, setProvider] = useState('');
  const [target, setTarget] = useState('');
  const [label, setLabel] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Keep the latest onCaptured without re-subscribing the listener each render.
  const onCapturedRef = useRef(onCaptured);
  onCapturedRef.current = onCaptured;
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Listen for the callback success page's postMessage. Trust only our message
  // type; the credential itself is never carried in the message (non-secret
  // signal only) so we simply trigger a reload of the credential list.
  useEffect(() => {
    function onMessage(ev: MessageEvent) {
      const data = ev.data as { type?: string } | null;
      if (data && data.type === OAUTH_CAPTURED) {
        setNotice('Captured the credential — refreshed the list below.');
        onCapturedRef.current?.();
      }
    }
    window.addEventListener('message', onMessage);
    return () => {
      window.removeEventListener('message', onMessage);
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  // Fallback poll: refresh the credential list a few times after opening the
  // consent tab, in case the postMessage never arrives (blocked opener, the
  // redirect points elsewhere, etc.).
  function startFallbackPoll() {
    if (pollRef.current) clearInterval(pollRef.current);
    let ticks = 0;
    pollRef.current = setInterval(() => {
      ticks += 1;
      onCapturedRef.current?.();
      if (ticks >= 6 && pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }, 5000);
  }

  async function onConnect(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setNotice(null);

    const p = provider.trim();
    if (!p) {
      setFormError('Enter a provider name.');
      return;
    }

    setSubmitting(true);
    try {
      const result = await api.startOAuth(passportId, p, {
        target: target.trim() || undefined,
        label: label.trim() || undefined,
      });
      // Open the consent screen in a new tab; the user finishes there. We must
      // NOT pass noopener/noreferrer here: those null window.opener in the popup,
      // which would prevent the server callback success page from posting the
      // capture message back to this window (the primary auto-refresh signal).
      // The fallback poll below covers the case where the message is still missed.
      window.open(result.authorizeUrl, '_blank');
      setNotice(
        `Opened ${p} consent in a new tab. Once you authorize, the captured ` +
          `credential will appear in the list below automatically.`,
      );
      startFallbackPoll();
      setProvider('');
      setTarget('');
      setLabel('');
    } catch (err) {
      setFormError(err);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h2>Connect an OAuth provider</h2>
      <p className="muted">
        Start a provider authorization flow for this passport. You&apos;ll
        complete consent in a new tab; the resulting token is sealed into the
        vault as a credential here.
      </p>

      {notice && <div className="alert success">{notice}</div>}
      <ErrorBanner error={formError} />

      <form onSubmit={onConnect}>
        <div className="row">
          <div className="field">
            <label htmlFor="oauth-provider">Provider</label>
            <input
              id="oauth-provider"
              placeholder="google"
              required
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="oauth-target">Target (optional)</label>
            <input
              id="oauth-target"
              placeholder="googleapis.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="oauth-label">Label (optional)</label>
            <input
              id="oauth-label"
              placeholder="Google workspace"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>
        </div>

        <button type="submit" disabled={submitting}>
          {submitting ? 'Starting…' : 'Connect provider'}
        </button>
      </form>
    </div>
  );
}
