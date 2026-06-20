'use client';

import { useEffect, useState, useCallback } from 'react';
import { api, MfaRequest } from '@/lib/api';
import RequireAuth from '../components/RequireAuth';
import ErrorBanner from '../components/ErrorBanner';

// Kinds where the human enters a one-time code; everything else (push,
// webauthn) is approved out-of-band on the user's device, so we just confirm.
const CODE_KINDS = new Set(['otp', 'totp', 'sms', 'email']);

function MfaView() {
  const [requests, setRequests] = useState<MfaRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  // Per-request one-time code input. Never logged.
  const [codes, setCodes] = useState<Record<string, string>>({});
  // Track which card is mid-action so we can disable its buttons.
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await api.listMfa(100, 0);
      setRequests(page.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function remove(id: string) {
    setRequests((prev) => prev.filter((r) => r.id !== id));
    setCodes((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }

  async function approve(req: MfaRequest) {
    setError(null);
    setActing(req.id);
    try {
      // Code kinds send the entered value; push/webauthn approve with no code.
      const code = CODE_KINDS.has(req.kind) ? codes[req.id] : undefined;
      await api.approveMfa(req.id, code);
      remove(req.id);
    } catch (err) {
      setError(err);
    } finally {
      setActing(null);
    }
  }

  async function deny(req: MfaRequest) {
    setError(null);
    setActing(req.id);
    try {
      await api.denyMfa(req.id);
      remove(req.id);
    } catch (err) {
      setError(err);
    } finally {
      setActing(null);
    }
  }

  return (
    <>
      <h1>MFA approvals</h1>
      <p className="muted">
        Step-up challenges raised while an agent used a credential. Approve with
        the one-time code, confirm a device push, or deny the attempt.
      </p>

      <ErrorBanner error={error} />

      {loading ? (
        <div className="card">
          <p className="muted">Loading…</p>
        </div>
      ) : requests.length === 0 ? (
        <div className="card">
          <p className="empty">No MFA requests waiting.</p>
        </div>
      ) : (
        requests.map((r) => {
          const isCode = CODE_KINDS.has(r.kind);
          const busy = acting === r.id;
          return (
            <div className="card" key={r.id}>
              <div className="flex-between">
                <h2 className="mono">{r.credentialId}</h2>
                <span className="chip">{r.kind}</span>
              </div>

              {r.promptText && <p>{r.promptText}</p>}

              <div className="muted" style={{ marginBottom: '0.75rem' }}>
                {r.channelHint && (
                  <div>
                    Channel: <span className="mono">{r.channelHint}</span>
                  </div>
                )}
                <div className="mono">agent {r.agentId}</div>
                <div className="mono">passport {r.passportId}</div>
                <div>Requested {new Date(r.createdAt).toLocaleString()}</div>
                {r.expiresAt && (
                  <div>Expires {new Date(r.expiresAt).toLocaleString()}</div>
                )}
              </div>

              {isCode ? (
                <div className="row">
                  <div className="field" style={{ flex: 1 }}>
                    <label htmlFor={`code-${r.id}`}>One-time code</label>
                    <input
                      id={`code-${r.id}`}
                      type="text"
                      inputMode="numeric"
                      autoComplete="off"
                      placeholder="123456"
                      value={codes[r.id] ?? ''}
                      onChange={(e) =>
                        setCodes((prev) => ({ ...prev, [r.id]: e.target.value }))
                      }
                    />
                  </div>
                  <button
                    disabled={busy || !(codes[r.id] ?? '').trim()}
                    onClick={() => approve(r)}
                  >
                    {busy ? 'Working…' : 'Approve'}
                  </button>
                  <button
                    className="btn-danger"
                    disabled={busy}
                    onClick={() => deny(r)}
                  >
                    Deny
                  </button>
                </div>
              ) : (
                <div className="row">
                  <button disabled={busy} onClick={() => approve(r)}>
                    {busy ? 'Working…' : 'I approved the push'}
                  </button>
                  <button
                    className="btn-danger"
                    disabled={busy}
                    onClick={() => deny(r)}
                  >
                    Deny
                  </button>
                </div>
              )}
            </div>
          );
        })
      )}
    </>
  );
}

export default function MfaPage() {
  return (
    <RequireAuth>
      <MfaView />
    </RequireAuth>
  );
}
