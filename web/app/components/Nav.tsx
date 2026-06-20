'use client';

import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import { api, isAuthenticated } from '@/lib/api';

/**
 * Top navigation bar. Renders the authed link set + logout only once the
 * client has hydrated and confirmed a token exists (localStorage is not
 * available during SSR, so we gate on a mount flag to avoid a flash/mismatch).
 */
export default function Nav() {
  const router = useRouter();
  const pathname = usePathname();
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    setAuthed(isAuthenticated());
  }, [pathname]);

  async function handleLogout() {
    await api.logout();
    setAuthed(false);
    router.push('/login');
  }

  return (
    <header className="topbar">
      <span className="brand">
        🛂 Agent<span className="accent">Auth</span>
      </span>
      <nav className="nav">
        {authed && (
          <>
            <Link href="/passports">Passports</Link>
            <Link href="/agents">Agents</Link>
            <Link href="/approvals">Approvals</Link>
            <Link href="/mfa">MFA</Link>
            <Link href="/audit">Audit</Link>
          </>
        )}
      </nav>
      {authed ? (
        <button className="btn-ghost" onClick={handleLogout}>
          Log out
        </button>
      ) : (
        <Link href="/login" className="btn btn-ghost">
          Log in
        </Link>
      )}
    </header>
  );
}
