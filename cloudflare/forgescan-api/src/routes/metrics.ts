import { Hono } from 'hono';
import type { Env } from '../index';
import { requireRole } from '../middleware/auth';

export const metrics = new Hono<{ Bindings: Env }>();

// ─────────────────────────────────────────────────────────────────────────────
// GET /metrics — Platform-level API metrics (platform_admin only)
// ─────────────────────────────────────────────────────────────────────────────
metrics.get('/', requireRole('platform_admin'), async (c) => {
  // Gather database counts in parallel
  const [assetCount, findingCount, scanCount, socAlertCount, activeScanners] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as count FROM assets').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM findings').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM scans').first<{ count: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as count FROM soc_alerts').first<{ count: number }>().catch(() => ({ count: 0 })),
    c.env.DB.prepare(
      "SELECT COUNT(*) as count FROM scanner_registrations WHERE last_heartbeat_at > datetime('now', '-5 minutes')"
    ).first<{ count: number }>().catch(() => ({ count: 0 })),
  ]);

  // Read recent metrics from KV (last 5 minutes)
  const metricsPrefix = 'metrics:';
  const metricsList = await c.env.CACHE.list({ prefix: metricsPrefix });

  let totalRequests = 0;
  let totalErrors = 0;
  let totalDuration = 0;
  const routeMap = new Map<string, { count: number; total_ms: number; max_ms: number; errors: number }>();

  for (const key of metricsList.keys) {
    const raw = await c.env.CACHE.get(key.name);
    if (!raw) continue;

    const data: { count: number; total_ms: number; max_ms: number } = JSON.parse(raw);

    // Parse key: metrics:{minute}:{method}:{path}:{statusBucket}
    const parts = key.name.split(':');
    const method = parts[2];
    const path = parts.slice(3, -1).join(':');
    const statusBucket = parts[parts.length - 1];

    const routeKey = `${method} ${path}`;
    const isError = statusBucket === '4xx' || statusBucket === '5xx';

    totalRequests += data.count;
    totalDuration += data.total_ms;
    if (isError) totalErrors += data.count;

    const existing = routeMap.get(routeKey) || { count: 0, total_ms: 0, max_ms: 0, errors: 0 };
    existing.count += data.count;
    existing.total_ms += data.total_ms;
    existing.max_ms = Math.max(existing.max_ms, data.max_ms);
    if (isError) existing.errors += data.count;
    routeMap.set(routeKey, existing);
  }

  const routes = Array.from(routeMap.entries())
    .map(([route, d]) => ({
      route,
      count: d.count,
      avg_ms: d.count > 0 ? Math.round(d.total_ms / d.count) : 0,
      max_ms: d.max_ms,
      error_count: d.errors,
    }))
    .sort((a, b) => b.count - a.count);

  return c.json({
    window: '5m',
    total_requests: totalRequests,
    error_count: totalErrors,
    avg_latency_ms: totalRequests > 0 ? Math.round(totalDuration / totalRequests) : 0,
    active_scanners: activeScanners?.count || 0,
    database: {
      assets: assetCount?.count || 0,
      findings: findingCount?.count || 0,
      scans: scanCount?.count || 0,
      soc_alerts: socAlertCount?.count || 0,
    },
    routes,
  });
});
