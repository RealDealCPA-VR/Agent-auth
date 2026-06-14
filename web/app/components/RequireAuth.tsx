'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { isAuthenticated } from '@/lib/api';

/**
 * Client-side route guard. Since the session token lives in localStorage,
 * auth can only be evaluated in the browser. We redirect to /login when no
 * token is present, and render nothing until the check completes to avoid
 * briefly flashing protected content.
 */
export default function RequireAuth({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace('/login');
      return;
    }
    setReady(true);
  }, [router]);

  if (!ready) return null;
  return <>{children}</>;
}
