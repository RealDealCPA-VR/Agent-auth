'use client';

import { useEffect, useState, useCallback } from 'react';
import { api, ApprovalRequest } from '@/lib/api';
import RequireAuth from '../components/RequireAuth';
import ErrorBanner from '../components/ErrorBanner';

function ApprovalsView() {
  const [requests, setRequests] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  // Track which row is mid-action so we can disable its buttons.
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await api.listApprovals(100, 0);
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

  async function decide(id: string, decision: 'approve' | 'deny') {
    setError(null);
    setActing(id);
    try {
      if (decision === 'approve') {
        await api.approveRequest(id);
      } else {
        await api.denyRequest(id);
      }
      // Reload for authoritative state after the decision.
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setActing(null);
    }
  }

  return (
    <>
      <h1>Approvals</h1>
      <p className="muted">
        Pending requests from agents to use a credential. Approve to release the
        secret for that request, or deny to reject it.
      </p>

      <ErrorBanner error={error} />

      <div className="card">
        <h2>Pending requests</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : requests.length === 0 ? (
          <p className="empty">No approval requests waiting.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Request</th>
                <th>Agent</th>
                <th>Credential</th>
                <th>Status</th>
                <th>Requested</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.id}>
                  <td>
                    <div className="muted mono">{r.id}</div>
                    <div className="muted mono">passport {r.passportId}</div>
                  </td>
                  <td className="mono">{r.agentId}</td>
                  <td className="mono">{r.credentialId}</td>
                  <td>
                    {r.status === 'pending' ? (
                      <span className="badge ok">pending</span>
                    ) : (
                      <span className="badge bad">{r.status}</span>
                    )}
                  </td>
                  <td className="muted">
                    {new Date(r.createdAt).toLocaleString()}
                  </td>
                  <td className="muted">
                    {r.expiresAt
                      ? new Date(r.expiresAt).toLocaleString()
                      : '—'}
                  </td>
                  <td>
                    {r.status === 'pending' && (
                      <div className="row">
                        <button
                          disabled={acting === r.id}
                          onClick={() => decide(r.id, 'approve')}
                        >
                          {acting === r.id ? 'Working…' : 'Approve'}
                        </button>
                        <button
                          className="btn-danger"
                          disabled={acting === r.id}
                          onClick={() => decide(r.id, 'deny')}
                        >
                          Deny
                        </button>
                      </div>
                    )}
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

export default function ApprovalsPage() {
  return (
    <RequireAuth>
      <ApprovalsView />
    </RequireAuth>
  );
}
