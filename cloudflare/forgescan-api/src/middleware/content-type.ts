/**
 * Content-Type enforcement middleware.
 * Requires Content-Type: application/json on POST/PUT/PATCH requests,
 * with exemptions for routes that accept other content types (e.g., file uploads).
 */
import { MiddlewareHandler } from 'hono';

/** Paths (prefixes) that accept non-JSON content types */
const EXEMPT_PATHS = [
  '/api/v1/ingest/',
  '/api/v1/import/',
  '/api/v1/scanner/',
];

/** Content types allowed on exempt paths */
const ALLOWED_UPLOAD_TYPES = [
  'application/json',
  'text/csv',
  'text/xml',
  'application/xml',
  'multipart/form-data',
];

export const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const method = c.req.method;

  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    const contentType = c.req.header('Content-Type') || '';
    const path = c.req.path;

    const isExempt = EXEMPT_PATHS.some((p) => path.startsWith(p));

    if (isExempt) {
      // Exempt paths must still have a recognized content type
      const hasValidType = ALLOWED_UPLOAD_TYPES.some((t) => contentType.includes(t));
      if (!hasValidType) {
        return c.json({
          error: 'Unsupported Media Type',
          message: `Content-Type must be one of: ${ALLOWED_UPLOAD_TYPES.join(', ')}`,
        }, 415);
      }
    } else {
      // Standard API endpoints require JSON
      if (!contentType.includes('application/json')) {
        return c.json({
          error: 'Unsupported Media Type',
          message: 'Content-Type must be application/json',
        }, 415);
      }
    }
  }

  return next();
};
