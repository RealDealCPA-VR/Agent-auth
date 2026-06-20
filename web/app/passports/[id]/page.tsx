'use client';

import { useEffect, useState, FormEvent, useCallback } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api, Credential, CredentialType } from '@/lib/api';
import RequireAuth from '../../components/RequireAuth';
import ErrorBanner from '../../components/ErrorBanner';
import OAuthConnect from './OAuthConnect';

const TYPES: CredentialType[] = ['password', 'oauth_token', 'cookie', 'api_key'];

// Browser-login spec stored under metadata.browser (a non-secret object the
// proxy uses to inject the credential into a real browser session).
type BrowserMode = 'none' | 'cookie' | 'header' | 'localStorage' | 'form';
const BROWSER_MODES: BrowserMode[] = [
  'none',
  'cookie',
  'header',
  'localStorage',
  'form',
];

function PassportDetailView({ passportId }: { passportId: string }) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  // Deposit form state.
  const [target, setTarget] = useState('');
  const [label, setLabel] = useState('');
  const [type, setType] = useState<CredentialType>('api_key');
  const [secret, setSecret] = useState('');
  const [metadata, setMetadata] = useState('');
  const [expiresAt, setExpiresAt] = useState('');

  // Usage policy fields (server accepts these on deposit).
  const [maxUses, setMaxUses] = useState('');
  const [allowedFrom, setAllowedFrom] = useState('');
  const [allowedUntil, setAllowedUntil] = useState('');
  const [requireApproval, setRequireApproval] = useState(false);

  // Browser-login spec (metadata.browser).
  const [browserMode, setBrowserMode] = useState<BrowserMode>('none');
  const [headerName, setHeaderName] = useState('Authorization');
  const [headerPrefix, setHeaderPrefix] = useState('Bearer ');
  const [lsOrigin, setLsOrigin] = useState('');
  const [lsKey, setLsKey] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formUserSelector, setFormUserSelector] = useState('');
  const [formPassSelector, setFormPassSelector] = useState('');
  const [formSubmitSelector, setFormSubmitSelector] = useState('');
  const [formSuccessIncludes, setFormSuccessIncludes] = useState('');
  const [formUsername, setFormUsername] = useState('');
  // Optional MFA spec (form mode): non-secret hints stored in metadata.browser.mfa.
  const [formMfaKind, setFormMfaKind] = useState('');
  const [formMfaChannelHint, setFormMfaChannelHint] = useState('');
  const [formMfaInputSelector, setFormMfaInputSelector] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await api.listCredentials(passportId, 100, 0);
      setCredentials(page.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [passportId]);

  useEffect(() => {
    load();
  }, [load]);

  async function onDeposit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setSuccess(null);

    // Metadata is an optional free-form JSON object that we merge the browser
    // login spec (and form username) into.
    let metadataObj: Record<string, unknown> = {};
    if (metadata.trim()) {
      try {
        const parsed = JSON.parse(metadata);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('Metadata must be a JSON object.');
        }
        metadataObj = parsed as Record<string, unknown>;
      } catch (err) {
        setFormError(
          err instanceof Error
            ? `Invalid metadata JSON: ${err.message}`
            : 'Invalid metadata JSON.',
        );
        return;
      }
    }

    // Build the browser-login spec and merge it into metadata.browser. `none`
    // omits the key entirely.
    if (browserMode !== 'none') {
      let browser: Record<string, unknown>;
      switch (browserMode) {
        case 'cookie':
          browser = { mode: 'cookie' };
          break;
        case 'header': {
          browser = { mode: 'header' };
          const h = headerName.trim();
          if (h) browser.header = h;
          // Prefix is intentionally not trimmed (e.g. "Bearer " ends in a space).
          if (headerPrefix) browser.prefix = headerPrefix;
          break;
        }
        case 'localStorage': {
          const origin = lsOrigin.trim();
          const key = lsKey.trim();
          if (!origin || !key) {
            setFormError(
              'localStorage browser login needs both an origin URL and a storage key.',
            );
            return;
          }
          browser = { mode: 'localStorage', origin, key };
          break;
        }
        case 'form': {
          const url = formUrl.trim();
          const passSel = formPassSelector.trim();
          if (!url || !passSel) {
            setFormError(
              'Form browser login needs a login URL and a password field selector.',
            );
            return;
          }
          const fields: Array<{ selector: string; valueFrom: 'username' | 'secret' }> =
            [];
          const userSel = formUserSelector.trim();
          const uname = formUsername.trim();
          // A username field selector references metadata.username; requiring the
          // value here prevents a spec that deposits fine but fails at use-time
          // with missing_username (the server's precheckBrowserSpec).
          if (userSel && !uname) {
            setFormError(
              'Provide a username value when a username field selector is set.',
            );
            return;
          }
          if (userSel) fields.push({ selector: userSel, valueFrom: 'username' });
          fields.push({ selector: passSel, valueFrom: 'secret' });
          browser = { mode: 'form', url, fields };
          const submitSel = formSubmitSelector.trim();
          if (submitSel) browser.submitSelector = submitSel;
          const successInc = formSuccessIncludes.trim();
          if (successInc) browser.successUrlIncludes = successInc;
          // Optional MFA hints (non-secret) for SDK-side detection/resolution.
          if (formMfaKind) {
            const mfa: Record<string, unknown> = { kind: formMfaKind };
            const hint = formMfaChannelHint.trim();
            const otpSel = formMfaInputSelector.trim();
            if (hint) mfa.channelHint = hint;
            if (otpSel) mfa.inputSelector = otpSel;
            browser.mfa = mfa;
          }
          // The form references metadata.username for the username field.
          if (uname) metadataObj.username = uname;
          break;
        }
        default:
          browser = { mode: browserMode };
      }
      metadataObj.browser = browser;
    }

    const hasMetadata = Object.keys(metadataObj).length > 0;
    const parsedMaxUses = maxUses.trim() ? Number(maxUses) : undefined;
    if (parsedMaxUses !== undefined && (!Number.isInteger(parsedMaxUses) || parsedMaxUses < 1)) {
      setFormError('Max uses must be a positive whole number.');
      return;
    }

    setSubmitting(true);
    try {
      const created = await api.depositCredential(passportId, {
        target: target.trim(),
        label: label.trim(),
        type,
        secret,
        metadata: hasMetadata ? metadataObj : undefined,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
        maxUses: parsedMaxUses,
        allowedFrom: allowedFrom ? new Date(allowedFrom).toISOString() : undefined,
        allowedUntil: allowedUntil
          ? new Date(allowedUntil).toISOString()
          : undefined,
        requireApproval: requireApproval || undefined,
      });
      setCredentials((prev) => [created, ...prev]);
      setSuccess(`Sealed “${created.label}” for ${created.target}.`);
      // Clear the secret immediately; keep target/type for quick repeats.
      setSecret('');
      setLabel('');
      setMetadata('');
      setExpiresAt('');
      setMaxUses('');
      setAllowedFrom('');
      setAllowedUntil('');
      setRequireApproval(false);
    } catch (err) {
      setFormError(err);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <p className="muted">
        <Link href="/passports">← Passports</Link>
      </p>
      <h1>Passport</h1>
      <p className="muted mono">{passportId}</p>

      <ErrorBanner error={error} />

      <div className="card">
        <h2>Deposit a credential</h2>
        <p className="muted">
          The secret is sealed with AES-256-GCM the moment it reaches the vault
          and is never shown again here.
        </p>

        {success && <div className="alert success">{success}</div>}
        <ErrorBanner error={formError} />

        <form onSubmit={onDeposit}>
          <div className="row">
            <div className="field">
              <label htmlFor="target">Target host</label>
              <input
                id="target"
                placeholder="github.com"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="label">Label</label>
              <input
                id="label"
                placeholder="GH personal token"
                required
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="type">Type</label>
              <select
                id="type"
                value={type}
                onChange={(e) => setType(e.target.value as CredentialType)}
              >
                {TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="field">
            <label htmlFor="secret">Secret</label>
            <input
              id="secret"
              type="password"
              autoComplete="off"
              placeholder="the value to seal"
              required
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </div>

          <div className="row">
            <div className="field">
              <label htmlFor="expires">Expires (optional)</label>
              <input
                id="expires"
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="metadata">Metadata JSON (optional)</label>
              <input
                id="metadata"
                placeholder='{"username":"me"}'
                value={metadata}
                onChange={(e) => setMetadata(e.target.value)}
              />
            </div>
          </div>

          <h3>Usage policy (optional)</h3>
          <div className="row">
            <div className="field">
              <label htmlFor="max-uses">Max uses</label>
              <input
                id="max-uses"
                type="number"
                min={1}
                step={1}
                placeholder="unlimited"
                value={maxUses}
                onChange={(e) => setMaxUses(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="allowed-from">Allowed from</label>
              <input
                id="allowed-from"
                type="datetime-local"
                value={allowedFrom}
                onChange={(e) => setAllowedFrom(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="allowed-until">Allowed until</label>
              <input
                id="allowed-until"
                type="datetime-local"
                value={allowedUntil}
                onChange={(e) => setAllowedUntil(e.target.value)}
              />
            </div>
          </div>
          <div className="field">
            <label
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                textTransform: 'none',
              }}
            >
              <input
                type="checkbox"
                style={{ width: 'auto' }}
                checked={requireApproval}
                onChange={(e) => setRequireApproval(e.target.checked)}
              />
              Require human approval
            </label>
          </div>

          <h3>Browser login (optional)</h3>
          <p className="muted">
            How the proxy injects this credential into a real browser session.
          </p>
          <div className="field">
            <label htmlFor="browser-mode">Mode</label>
            <select
              id="browser-mode"
              value={browserMode}
              onChange={(e) => setBrowserMode(e.target.value as BrowserMode)}
            >
              {BROWSER_MODES.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          {browserMode === 'header' && (
            <div className="row">
              <div className="field">
                <label htmlFor="browser-header">Header name</label>
                <input
                  id="browser-header"
                  placeholder="Authorization"
                  value={headerName}
                  onChange={(e) => setHeaderName(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="browser-prefix">Prefix</label>
                <input
                  id="browser-prefix"
                  placeholder="Bearer "
                  value={headerPrefix}
                  onChange={(e) => setHeaderPrefix(e.target.value)}
                />
              </div>
            </div>
          )}

          {browserMode === 'localStorage' && (
            <div className="row">
              <div className="field">
                <label htmlFor="browser-ls-origin">Origin URL</label>
                <input
                  id="browser-ls-origin"
                  placeholder="https://app.example.com"
                  value={lsOrigin}
                  onChange={(e) => setLsOrigin(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="browser-ls-key">Storage key</label>
                <input
                  id="browser-ls-key"
                  placeholder="auth.token"
                  value={lsKey}
                  onChange={(e) => setLsKey(e.target.value)}
                />
              </div>
            </div>
          )}

          {browserMode === 'form' && (
            <>
              <div className="row">
                <div className="field">
                  <label htmlFor="browser-form-url">Login URL</label>
                  <input
                    id="browser-form-url"
                    placeholder="https://app.example.com/login"
                    value={formUrl}
                    onChange={(e) => setFormUrl(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="browser-form-username">Username</label>
                  <input
                    id="browser-form-username"
                    placeholder="me@example.com"
                    value={formUsername}
                    onChange={(e) => setFormUsername(e.target.value)}
                  />
                </div>
              </div>
              <div className="row">
                <div className="field">
                  <label htmlFor="browser-form-user-sel">
                    Username field selector (optional)
                  </label>
                  <input
                    id="browser-form-user-sel"
                    placeholder="#username"
                    value={formUserSelector}
                    onChange={(e) => setFormUserSelector(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="browser-form-pass-sel">
                    Password field selector
                  </label>
                  <input
                    id="browser-form-pass-sel"
                    placeholder="#password"
                    value={formPassSelector}
                    onChange={(e) => setFormPassSelector(e.target.value)}
                  />
                </div>
              </div>
              <div className="row">
                <div className="field">
                  <label htmlFor="browser-form-submit-sel">
                    Submit selector (optional)
                  </label>
                  <input
                    id="browser-form-submit-sel"
                    placeholder="button[type=submit]"
                    value={formSubmitSelector}
                    onChange={(e) => setFormSubmitSelector(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="browser-form-success">
                    Success URL includes (optional)
                  </label>
                  <input
                    id="browser-form-success"
                    placeholder="/dashboard"
                    value={formSuccessIncludes}
                    onChange={(e) => setFormSuccessIncludes(e.target.value)}
                  />
                </div>
              </div>
              <div className="row">
                <div className="field">
                  <label htmlFor="browser-form-mfa-kind">
                    MFA kind (optional — enables human-in-the-loop MFA)
                  </label>
                  <select
                    id="browser-form-mfa-kind"
                    value={formMfaKind}
                    onChange={(e) => setFormMfaKind(e.target.value)}
                  >
                    <option value="">none</option>
                    <option value="totp">totp (authenticator app)</option>
                    <option value="otp">otp</option>
                    <option value="sms">sms</option>
                    <option value="email">email</option>
                    <option value="push">push</option>
                    <option value="webauthn">webauthn</option>
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="browser-form-mfa-hint">
                    MFA channel hint (shown to approver, optional)
                  </label>
                  <input
                    id="browser-form-mfa-hint"
                    placeholder="code from your authenticator app"
                    value={formMfaChannelHint}
                    onChange={(e) => setFormMfaChannelHint(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label htmlFor="browser-form-mfa-sel">
                    MFA code input selector (optional)
                  </label>
                  <input
                    id="browser-form-mfa-sel"
                    placeholder="#otp"
                    value={formMfaInputSelector}
                    onChange={(e) => setFormMfaInputSelector(e.target.value)}
                  />
                </div>
              </div>
            </>
          )}

          <button type="submit" disabled={submitting}>
            {submitting ? 'Sealing…' : 'Deposit credential'}
          </button>
        </form>
      </div>

      <OAuthConnect passportId={passportId} onCaptured={load} />

      <div className="card">
        <h2>Credentials</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : credentials.length === 0 ? (
          <p className="empty">No credentials deposited yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Target</th>
                <th>Type</th>
                <th>Expires</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((c) => (
                <tr key={c.id}>
                  <td>
                    {c.label}
                    <div className="muted mono">{c.id}</div>
                  </td>
                  <td className="mono">{c.target}</td>
                  <td>
                    <span className="chip">{c.type}</span>
                  </td>
                  <td className="muted">
                    {c.expiresAt
                      ? new Date(c.expiresAt).toLocaleString()
                      : '—'}
                  </td>
                  <td className="muted">
                    {new Date(c.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

export default function PassportDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  if (!id) return null;
  return (
    <RequireAuth>
      <PassportDetailView passportId={id} />
    </RequireAuth>
  );
}
