'use client';

import { useEffect, useState, useCallback } from 'react';
import { api, AuditEvent, AuditVerifyResult } from '@/lib/api';
import RequireAuth from '../components/RequireAuth';
import ErrorBanner from '../components/ErrorBanner';

/**
 * Pull a few well-known display fields off an audit event, tolerating the
 * open-ended payload shape. Anything we can't place falls into the raw column.
 */
function field(ev: AuditEvent, ...keys: string[]): string {
  for (const k of keys) {
    const v = ev[k];
    if (typeof v === 'string' && v) return v;
    if (typeof v === 'number') return String(v);
  }
  return '';
}

function AuditView() {
  const PAGE = 100;
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const [verify, setVerify] = useState<AuditVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Offset-based paging: load(0) replaces; load(events.length) appends the next
  // page, so the full audit history is reachable, not just the newest 100.
  const load = useCallback(async (offset = 0) => {
    setError(null);
    try {
      const page = await api.listAudit(PAGE, offset);
      setEvents((prev) => (offset === 0 ? page.items : [...prev, ...page.items]));
      setTotal(page.pagination?.total ?? 0);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onVerify() {
    setVerifying(true);
    setVerify(null);
    setError(null);
    try {
      setVerify(await api.verifyAudit());
    } catch (err) {
      setError(err);
    } finally {
      setVerifying(false);
    }
  }

  return (
    <>
      <div className="flex-between">
        <h1>Audit log</h1>
        <button onClick={onVerify} disabled={verifying}>
          {verifying ? 'Verifying…' : 'Verify integrity'}
        </button>
      </div>
      <p className="muted">
        Every deposit, issue, use, revoke, and denial is appended to an HMAC
        hash-chained log. Verification recomputes the chain end to end.
      </p>

      <ErrorBanner error={error} />

      {verify &&
        (verify.ok ? (
          <div className="alert success">
            <strong>Chain intact.</strong> No tampering detected.
          </div>
        ) : (
          <div className="alert error">
            <strong>Chain broken.</strong> Tampering detected in the audit log.
          </div>
        ))}

      <div className="card">
        {loading ? (
          <p className="muted">Loading…</p>
        ) : events.length === 0 ? (
          <p className="empty">No audit events yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Event</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Target</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => {
                const when = field(ev, 'createdAt', 'timestamp', 'at');
                // Actor = who acted: the human (principalId) for owner actions,
                // else the agent (agentId) for agent actions. The affected target
                // lives inside `detail` (else fall back to credentialId).
                const actor = field(ev, 'principalId', 'agentId');
                const detail = (ev.detail ?? {}) as Record<string, unknown>;
                const target =
                  typeof detail.target === 'string' && detail.target
                    ? detail.target
                    : field(ev, 'credentialId');
                const idShort = field(ev, 'id').slice(0, 8);
                return (
                  <tr key={field(ev, 'id') || i}>
                    <td className="mono">{idShort || '—'}</td>
                    <td>
                      <span className="chip">
                        {field(ev, 'action', 'type', 'event') || 'event'}
                      </span>
                    </td>
                    <td className="mono">{actor || '—'}</td>
                    <td className="mono">{target || '—'}</td>
                    <td className="muted">
                      {when ? new Date(when).toLocaleString() : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {!loading && events.length < total && (
          <div className="flex-between" style={{ marginTop: '0.75rem' }}>
            <span className="muted">
              Showing {events.length} of {total}
            </span>
            <button onClick={() => load(events.length)}>Load more</button>
          </div>
        )}
      </div>
    </>
  );
}

export default function AuditPage() {
  return (
    <RequireAuth>
      <AuditView />
    </RequireAuth>
  );
}
