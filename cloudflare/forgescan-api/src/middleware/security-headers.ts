/**
 * Security response headers middleware.
 * Adds standard security headers to all responses to mitigate
 * common browser-based attacks (clickjacking, MIME sniffing, XSS).
 */
import { MiddlewareHandler } from 'hono';

export const securityHeaders: MiddlewareHandler = async (c, next) => {
  await next();

  // Prevent clickjacking
  c.header('X-Frame-Options', 'DENY');

  // Prevent MIME-type sniffing
  c.header('X-Content-Type-Options', 'nosniff');

  // XSS protection (legacy browsers)
  c.header('X-XSS-Protection', '1; mode=block');

  // Control referrer information
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Restrict resource loading — API-only, so very restrictive
  c.header(
    'Content-Security-Policy',
    "default-src 'none'; frame-ancestors 'none'",
  );

  // Opt out of FLoC and Topics
  c.header('Permissions-Policy', 'interest-cohort=(), browsing-topics=()');
};
