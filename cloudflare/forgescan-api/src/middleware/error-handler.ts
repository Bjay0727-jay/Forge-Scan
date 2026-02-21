/**
 * Global error handler middleware for the ForgeScan API.
 *
 * Catches all errors thrown from route handlers and returns a consistent
 * JSON error response. Known `ApiError` instances are serialised as-is;
 * unexpected errors are logged and masked before sending to the client.
 */
import type { ErrorHandler } from 'hono';
import { ApiError, ErrorCode } from '../lib/errors';

export const errorHandler: ErrorHandler = (err, c) => {
  // Known, intentional error – send as-is
  if (err instanceof ApiError) {
    console.error(`[${err.code}] ${err.status} ${err.message}`);
    return c.json(err.toJSON(), err.status as any);
  }

  // JSON parse / body errors (Hono throws these when c.req.json() fails)
  if (err instanceof SyntaxError && err.message.includes('JSON')) {
    console.error('[INVALID_INPUT] 400 Malformed JSON body');
    const apiErr = new ApiError(400, ErrorCode.INVALID_INPUT, 'Malformed JSON in request body');
    return c.json(apiErr.toJSON(), 400);
  }

  // Everything else: log the full stack but return a sanitised message
  console.error('[INTERNAL_ERROR] 500 Unhandled:', err);
  const apiErr = new ApiError(500, ErrorCode.INTERNAL_ERROR, 'An internal error occurred');
  return c.json(apiErr.toJSON(), 500);
};
