'use client';

import { ApiError } from '@/lib/api';

/**
 * Renders an error from the API in a consistent banner. Knows how to unwrap
 * the ApiError envelope (code + requestId) for easier debugging.
 */
export default function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;

  let message = 'Something went wrong.';
  let code: string | undefined;
  let requestId: string | undefined;

  if (error instanceof ApiError) {
    message = error.message;
    code = error.code;
    requestId = error.requestId;
  } else if (error instanceof Error) {
    message = error.message;
  } else if (typeof error === 'string') {
    message = error;
  }

  return (
    <div className="alert error" role="alert">
      <strong>{message}</strong>
      {(code || requestId) && (
        <div className="muted" style={{ marginTop: 4 }}>
          {code && <span className="mono">{code}</span>}
          {code && requestId && ' · '}
          {requestId && <span className="mono">req {requestId}</span>}
        </div>
      )}
    </div>
  );
}
