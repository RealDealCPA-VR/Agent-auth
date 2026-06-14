'use client';

import { useState, FormEvent } from 'react';
import { api } from '@/lib/api';
import ErrorBanner from '../../components/ErrorBanner';

/**
 * "Connect an OAuth provider" form. Starts the provider authorization flow for
 * this passport and opens the returned authorizeUrl in a new tab so the user
 * can complete consent. Once authorized, the captured credential shows up in
 * the passport's credential list (the server deposits it on callback).
 */
export default function OAuthConnect({ passportId }: { passportId: string }) {
  const [provider, setProvider] = useState('');
  const [target, setTarget] = useState('');
  const [label, setLabel] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
      // Open the consent screen in a new tab; the user finishes there.
      window.open(result.authorizeUrl, '_blank', 'noopener,noreferrer');
      setNotice(
        `Opened ${p} consent in a new tab. Once you authorize, the captured ` +
          `credential will appear in the list below — refresh after completing it.`,
      );
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
