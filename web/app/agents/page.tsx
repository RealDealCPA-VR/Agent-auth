'use client';

import { useEffect, useState, FormEvent, useCallback } from 'react';
import { api, Agent, Passport, IssuedAgent } from '@/lib/api';
import RequireAuth from '../components/RequireAuth';
import ErrorBanner from '../components/ErrorBanner';

function AgentsView() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [passports, setPassports] = useState<Passport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  // Issue form state.
  const [passportId, setPassportId] = useState('');
  const [name, setName] = useState('');
  const [scopeRead, setScopeRead] = useState(true);
  const [scopeUse, setScopeUse] = useState(true);
  const [targets, setTargets] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<unknown>(null);

  // The freshly-issued key, shown exactly once.
  const [issued, setIssued] = useState<IssuedAgent | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [agentsPage, passportsPage] = await Promise.all([
        api.listAgents(100, 0),
        api.listPassports(100, 0),
      ]);
      setAgents(agentsPage.items);
      setPassports(passportsPage.items);
      // Default the form to the first passport for convenience.
      if (!passportId && passportsPage.items.length > 0) {
        setPassportId(passportsPage.items[0].id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
    // passportId intentionally omitted: we only seed the default once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function buildScopes(): string[] {
    const scopes: string[] = [];
    if (scopeRead) scopes.push('vault:read');
    if (scopeUse) scopes.push('vault:use');
    for (const raw of targets.split(',')) {
      const t = raw.trim();
      if (!t) continue;
      // Allow the user to pass either "github.com" or "target:github.com".
      scopes.push(t.startsWith('target:') ? t : `target:${t}`);
    }
    return scopes;
  }

  async function onIssue(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    setIssued(null);

    if (!passportId) {
      setFormError('Select a passport to bind this agent to.');
      return;
    }
    const scopes = buildScopes();
    if (scopes.length === 0) {
      setFormError('Grant at least one scope.');
      return;
    }

    setSubmitting(true);
    try {
      const result = await api.issueAgent({
        passportId,
        name: name.trim(),
        scopes,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : undefined,
      });
      setIssued(result);
      setName('');
      setTargets('');
      setExpiresAt('');
      // Refresh the list so the new agent appears.
      const page = await api.listAgents(100, 0);
      setAgents(page.items);
    } catch (err) {
      setFormError(err);
    } finally {
      setSubmitting(false);
    }
  }

  async function onRevoke(id: string) {
    setError(null);
    try {
      await api.revokeAgent(id);
      // Optimistically mark inactive; reload for authoritative state.
      setAgents((prev) =>
        prev.map((a) =>
          a.id === id
            ? { ...a, active: false, revokedAt: new Date().toISOString() }
            : a,
        ),
      );
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <h1>Agents</h1>
      <p className="muted">
        Mint a scoped API key bound to a passport. The key is shown once —
        copy it now; it is never recoverable.
      </p>

      <ErrorBanner error={error} />

      {issued && (
        <div className="card">
          <div className="alert warn">
            <strong>Copy this API key now.</strong> {issued.warning}
          </div>
          <label>Agent API key</label>
          <div className="secret-box">{issued.apiKey}</div>
          <div className="row">
            <button
              className="btn-ghost"
              onClick={() => navigator.clipboard?.writeText(issued.apiKey)}
            >
              Copy to clipboard
            </button>
            <button className="btn-ghost" onClick={() => setIssued(null)}>
              I&apos;ve saved it — dismiss
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Issue an agent</h2>
        <ErrorBanner error={formError} />
        <form onSubmit={onIssue}>
          <div className="row">
            <div className="field">
              <label htmlFor="ag-passport">Passport</label>
              <select
                id="ag-passport"
                value={passportId}
                onChange={(e) => setPassportId(e.target.value)}
              >
                {passports.length === 0 && (
                  <option value="">No passports — create one first</option>
                )}
                {passports.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="ag-name">Name</label>
              <input
                id="ag-name"
                placeholder="ci-bot"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          </div>

          <div className="field">
            <label>Scopes</label>
            <div>
              <label
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  textTransform: 'none',
                  marginRight: 16,
                }}
              >
                <input
                  type="checkbox"
                  style={{ width: 'auto' }}
                  checked={scopeRead}
                  onChange={(e) => setScopeRead(e.target.checked)}
                />
                vault:read
              </label>
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
                  checked={scopeUse}
                  onChange={(e) => setScopeUse(e.target.checked)}
                />
                vault:use
              </label>
            </div>
          </div>

          <div className="row">
            <div className="field">
              <label htmlFor="ag-targets">
                Target globs (comma-separated)
              </label>
              <input
                id="ag-targets"
                placeholder="github.com, *.internal, *"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="ag-expires">Expires (optional)</label>
              <input
                id="ag-expires"
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting || passports.length === 0}
          >
            {submitting ? 'Issuing…' : 'Issue agent key'}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Your agents</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : agents.length === 0 ? (
          <p className="empty">No agents issued yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Scopes</th>
                <th>Status</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id}>
                  <td>
                    {a.name}
                    <div className="muted mono">{a.id}</div>
                  </td>
                  <td>
                    {a.scopes.map((s) => (
                      <span className="chip" key={s}>
                        {s}
                      </span>
                    ))}
                  </td>
                  <td>
                    {!a.active || a.revokedAt ? (
                      <span className="badge bad">revoked</span>
                    ) : a.expiresAt && new Date(a.expiresAt).getTime() <= Date.now() ? (
                      <span className="badge warn">expired</span>
                    ) : (
                      <span className="badge ok">active</span>
                    )}
                  </td>
                  <td className="muted">
                    {a.lastUsedAt
                      ? new Date(a.lastUsedAt).toLocaleString()
                      : '—'}
                  </td>
                  <td>
                    {a.active && (
                      <button
                        className="btn-danger"
                        onClick={() => onRevoke(a.id)}
                      >
                        Revoke
                      </button>
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

export default function AgentsPage() {
  return (
    <RequireAuth>
      <AgentsView />
    </RequireAuth>
  );
}
