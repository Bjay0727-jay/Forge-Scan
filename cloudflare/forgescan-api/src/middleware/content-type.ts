/**
 * Content-Type enforcement middleware.
 * Requires Content-Type: application/json on POST/PUT/PATCH requests.
 */
import { MiddlewareHandler } from 'hono';

export const requireJsonContentType: MiddlewareHandler = async (c, next) => {
  const method = c.req.method;

  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    const contentType = c.req.header('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return c.json({
        error: 'Unsupported Media Type',
        message: 'Content-Type must be application/json',
      }, 415);
    }
  }

  return next();
};
