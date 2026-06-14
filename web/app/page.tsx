'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { isAuthenticated } from '@/lib/api';

/**
 * Root route. Bounces to /passports when signed in, otherwise to /login.
 * Auth lives in localStorage, so the decision must happen client-side.
 */
export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace(isAuthenticated() ? '/passports' : '/login');
  }, [router]);
  return <p className="muted">Loading…</p>;
}
