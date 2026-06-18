'use client';

import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import ErrorBanner from '../components/ErrorBanner';

type Mode = 'login' | 'register';

/**
 * Combined login / register screen. Registering does NOT auto-create a
 * session (the API's POST /principals returns only {id,email}), so after a
 * successful registration we immediately log in with the same credentials.
 */
export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'register') {
        await api.register(email, password);
      }
      // Login in both flows — register response carries no token.
      await api.login(email, password);
      router.push('/passports');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center-page">
      <h1>{mode === 'login' ? 'Sign in' : 'Create account'}</h1>
      <p className="muted">
        {mode === 'login'
          ? 'Access your passports, agents, and audit log.'
          : 'Register a principal to start depositing credentials.'}
      </p>

      <ErrorBanner error={error} />

      <form onSubmit={onSubmit} className="card">
        <div className="field">
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            required
            minLength={mode === 'register' ? 10 : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" disabled={busy} style={{ width: '100%' }}>
          {busy
            ? 'Working…'
            : mode === 'login'
            ? 'Sign in'
            : 'Register & sign in'}
        </button>
      </form>

      <p className="muted" style={{ textAlign: 'center' }}>
        {mode === 'login' ? "Don't have an account? " : 'Already registered? '}
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setError(null);
            setMode(mode === 'login' ? 'register' : 'login');
          }}
        >
          {mode === 'login' ? 'Register' : 'Sign in'}
        </a>
      </p>
    </div>
  );
}
