/**
 * Request body size limit middleware.
 * Rejects payloads exceeding the configured maximum to prevent
 * resource exhaustion and abuse.
 */
import { MiddlewareHandler } from 'hono';

interface BodyLimitOptions {
  /** Maximum body size in bytes (default 1MB) */
  maxSize?: number;
}

/** Paths that allow larger uploads (e.g., scan file ingestion) */
const LARGE_UPLOAD_PATHS = [
  '/api/v1/ingest/',
  '/api/v1/import/',
];

const DEFAULT_MAX_SIZE = 1 * 1024 * 1024;        // 1 MB
const LARGE_UPLOAD_MAX_SIZE = 100 * 1024 * 1024;  // 100 MB

export function bodyLimitMiddleware(options: BodyLimitOptions = {}): MiddlewareHandler {
  const defaultMax = options.maxSize ?? DEFAULT_MAX_SIZE;

  return async (c, next) => {
    // Only check body-bearing methods
    if (!['POST', 'PUT', 'PATCH'].includes(c.req.method)) {
      return next();
    }

    const contentLength = c.req.header('Content-Length');
    if (!contentLength) {
      // No Content-Length header — allow through (chunked transfer or small body)
      return next();
    }

    const size = parseInt(contentLength, 10);
    if (isNaN(size)) {
      return next();
    }

    const path = c.req.path;
    const isLargeUpload = LARGE_UPLOAD_PATHS.some((p) => path.startsWith(p));
    const limit = isLargeUpload ? LARGE_UPLOAD_MAX_SIZE : defaultMax;

    if (size > limit) {
      const limitMB = Math.round(limit / (1024 * 1024));
      return c.json({
        error: 'Payload Too Large',
        message: `Request body exceeds maximum size of ${limitMB}MB`,
      }, 413);
    }

    return next();
  };
}
