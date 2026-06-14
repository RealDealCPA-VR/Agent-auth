'use client';

import { useEffect, useState, FormEvent, useCallback } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { api, Credential, CredentialType } from '@/lib/api';
import RequireAuth from '../../components/RequireAuth';
import ErrorBanner from '../../components/ErrorBanner';

const TYPES: CredentialType[] = ['password', 'oauth_token', 'cookie', 'api_key'];

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

    // Metadata is an optional free-form JSON object.
    let metadataObj: Record<string, unknown> | undefined;
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

    setSubmitting(true);
    try {
      const created = await api.depositCredential(passportId, {
        target: target.trim(),
        label: label.trim(),
        type,
        secret,
        metadata: metadataObj,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      });
      setCredentials((prev) => [created, ...prev]);
      setSuccess(`Sealed “${created.label}” for ${created.target}.`);
      // Clear the secret immediately; keep target/type for quick repeats.
      setSecret('');
      setLabel('');
      setMetadata('');
      setExpiresAt('');
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

          <button type="submit" disabled={submitting}>
            {submitting ? 'Sealing…' : 'Deposit credential'}
          </button>
        </form>
      </div>

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
