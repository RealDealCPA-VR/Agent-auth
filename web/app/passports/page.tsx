'use client';

import { useEffect, useState, FormEvent, useCallback } from 'react';
import Link from 'next/link';
import { api, Passport } from '@/lib/api';
import RequireAuth from '../components/RequireAuth';
import ErrorBanner from '../components/ErrorBanner';

function PassportsView() {
  const [passports, setPassports] = useState<Passport[]>([]);
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const page = await api.listPassports(100, 0);
      setPassports(page.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await api.createPassport(name.trim());
      setPassports((prev) => [created, ...prev]);
      setName('');
    } catch (err) {
      setError(err);
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <h1>Passports</h1>
      <p className="muted">
        A passport is a sealed vault of your credentials. Open one, deposit
        secrets, then mint scoped agents against it.
      </p>

      <ErrorBanner error={error} />

      <div className="card">
        <h2>New passport</h2>
        <form onSubmit={onCreate} className="row">
          <div className="field">
            <label htmlFor="pp-name">Name</label>
            <input
              id="pp-name"
              placeholder="e.g. work, personal, ci"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button type="submit" disabled={creating || !name.trim()}>
              {creating ? 'Creating…' : 'Create passport'}
            </button>
          </div>
        </form>
      </div>

      <div className="card">
        <h2>Your passports</h2>
        {loading ? (
          <p className="muted">Loading…</p>
        ) : passports.length === 0 ? (
          <p className="empty">No passports yet — create one above.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {passports.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link href={`/passports/${p.id}`}>{p.name}</Link>
                    <div className="muted mono">{p.id}</div>
                  </td>
                  <td className="muted">
                    {new Date(p.createdAt).toLocaleString()}
                  </td>
                  <td>
                    <Link href={`/passports/${p.id}`} className="btn btn-ghost">
                      Open
                    </Link>
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

export default function PassportsPage() {
  return (
    <RequireAuth>
      <PassportsView />
    </RequireAuth>
  );
}
