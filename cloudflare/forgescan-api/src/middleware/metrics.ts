import { MiddlewareHandler } from 'hono';

type MetricsEnv = {
  Bindings: {
    CACHE: KVNamespace;
  };
};

/**
 * Request metrics middleware.
 *
 * Records per-request timing and status data into KV, bucketed by minute.
 * Data is aggregated at read time via the /metrics endpoint.
 */
export const metricsMiddleware: MiddlewareHandler<MetricsEnv> = async (c, next) => {
  const start = Date.now();

  await next();

  const duration = Date.now() - start;
  const status = c.res.status;
  const method = c.req.method;

  // Normalise path: strip IDs/UUIDs to group by route pattern
  const path = c.req.path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id')
    .replace(/\/\d+/g, '/:id');

  const statusBucket = `${Math.floor(status / 100)}xx`;
  const minute = new Date().toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM

  const key = `metrics:${minute}:${method}:${path}:${statusBucket}`;

  try {
    const existing = await c.env.CACHE.get(key);
    let data: { count: number; total_ms: number; max_ms: number };

    if (existing) {
      data = JSON.parse(existing);
      data.count += 1;
      data.total_ms += duration;
      data.max_ms = Math.max(data.max_ms, duration);
    } else {
      data = { count: 1, total_ms: duration, max_ms: duration };
    }

    // TTL of 5 minutes — metrics are ephemeral
    await c.env.CACHE.put(key, JSON.stringify(data), { expirationTtl: 300 });
  } catch {
    // Non-critical: don't fail requests if metrics recording fails
  }
};
