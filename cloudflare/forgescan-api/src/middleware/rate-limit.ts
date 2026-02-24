import { MiddlewareHandler } from 'hono';

interface RateLimitOptions {
  limit: number;
  windowMs: number;
  keyPrefix?: string;
}

type RateLimitEnv = {
  Bindings: {
    CACHE: KVNamespace;
  };
};

/**
 * Sliding-window rate limiter backed by Cloudflare KV.
 *
 * Tracks request counts per client IP within a fixed time window.
 * Returns 429 Too Many Requests with a Retry-After header when exceeded.
 */
export function rateLimitMiddleware(options: RateLimitOptions): MiddlewareHandler<RateLimitEnv> {
  const { limit, windowMs, keyPrefix = 'general' } = options;
  const windowSeconds = Math.ceil(windowMs / 1000);

  return async (c, next) => {
    // Skip rate limiting for OPTIONS (CORS preflight)
    if (c.req.method === 'OPTIONS') {
      return next();
    }

    const ip = c.req.header('CF-Connecting-IP')
      || c.req.header('X-Forwarded-For')?.split(',')[0]?.trim()
      || 'unknown';

    // Bucket by fixed time windows
    const windowId = Math.floor(Date.now() / windowMs);
    const key = `rl:${keyPrefix}:${ip}:${windowId}`;

    try {
      const current = await c.env.CACHE.get(key);
      const count = current ? parseInt(current, 10) : 0;

      if (count >= limit) {
        const windowStart = windowId * windowMs;
        const windowEnd = windowStart + windowMs;
        const retryAfter = Math.ceil((windowEnd - Date.now()) / 1000);

        return c.json(
          {
            error: {
              code: 'RATE_LIMITED',
              message: 'Too many requests. Please try again later.',
            },
          },
          { status: 429, headers: { 'Retry-After': String(Math.max(retryAfter, 1)) } },
        );
      }

      // Increment counter with TTL matching the window
      await c.env.CACHE.put(key, String(count + 1), { expirationTtl: windowSeconds });
    } catch {
      // If KV is unavailable, allow the request through rather than blocking
    }

    return next();
  };
}
