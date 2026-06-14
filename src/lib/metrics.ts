/**
 * Minimal, dependency-free Prometheus-style metrics. Tracks counts only — no
 * secrets, no high-cardinality labels. Exposed at /metrics.
 */
const counters = new Map<string, number>();

function key(name: string, labels?: Record<string, string>): string {
  if (!labels) return name;
  const parts = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${v}"`);
  return `${name}{${parts.join(',')}}`;
}

export function inc(name: string, labels?: Record<string, string>, by = 1): void {
  const k = key(name, labels);
  counters.set(k, (counters.get(k) ?? 0) + by);
}

export function render(uptimeSeconds: number): string {
  const lines: string[] = [
    '# HELP agentauth_http_requests_total HTTP requests by method and status class.',
    '# TYPE agentauth_http_requests_total counter',
  ];
  for (const [k, v] of counters) lines.push(`${k} ${v}`);
  lines.push('# HELP agentauth_uptime_seconds Process uptime in seconds.');
  lines.push('# TYPE agentauth_uptime_seconds gauge');
  lines.push(`agentauth_uptime_seconds ${Math.floor(uptimeSeconds)}`);
  return lines.join('\n') + '\n';
}
