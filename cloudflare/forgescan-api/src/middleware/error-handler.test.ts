import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { notFound, badRequest, databaseError } from '../lib/errors';
import { errorHandler } from './error-handler';

/** Shape returned by every error response. */
interface ErrorBody {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}

/**
 * Integration tests for the global error handler.
 * Creates a minimal Hono app with the handler and verifies response shapes.
 */
function createTestApp() {
  const app = new Hono();
  app.onError(errorHandler);

  // Route that throws a known ApiError
  app.get('/not-found', () => {
    throw notFound('Widget', '42');
  });

  // Route that throws badRequest
  app.get('/bad-request', () => {
    throw badRequest('Invalid input');
  });

  // Route that throws a database error
  app.get('/db-error', () => {
    throw databaseError(new Error('UNIQUE constraint failed'));
  });

  // Route that throws a raw Error (unexpected)
  app.get('/unexpected', () => {
    throw new Error('Something totally unexpected');
  });

  // Route that throws a SyntaxError (malformed JSON)
  app.get('/bad-json', () => {
    throw new SyntaxError('Unexpected end of JSON input');
  });

  // Route that throws an Error with no message
  app.get('/empty-error', () => {
    throw new Error();
  });

  return app;
}

describe('errorHandler', () => {
  const app = createTestApp();

  it('returns structured JSON for ApiError (404)', async () => {
    const res = await app.request('/not-found');
    expect(res.status).toBe(404);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('NOT_FOUND');
    expect(body.error.message).toContain('Widget');
  });

  it('returns structured JSON for ApiError (400)', async () => {
    const res = await app.request('/bad-request');
    expect(res.status).toBe(400);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('VALIDATION_ERROR');
    expect(body.error.message).toBe('Invalid input');
  });

  it('masks database errors and returns 500', async () => {
    const res = await app.request('/db-error');
    expect(res.status).toBe(500);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('DATABASE_ERROR');
    // Should not leak raw SQL error
    expect(body.error.message).not.toContain('UNIQUE');
    expect(body.error.message).toContain('already exists');
  });

  it('returns 500 with generic message for unexpected errors', async () => {
    const res = await app.request('/unexpected');
    expect(res.status).toBe(500);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('INTERNAL_ERROR');
    // Should NOT leak the original error message
    expect(body.error.message).toBe('An internal error occurred');
    expect(body.error.message).not.toContain('Something totally unexpected');
  });

  it('handles malformed JSON SyntaxError as 400', async () => {
    const res = await app.request('/bad-json');
    expect(res.status).toBe(400);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('INVALID_INPUT');
    expect(body.error.message).toContain('Malformed JSON');
  });

  it('handles generic Error as 500', async () => {
    const res = await app.request('/empty-error');
    expect(res.status).toBe(500);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('INTERNAL_ERROR');
    expect(body.error.message).toBe('An internal error occurred');
  });

  it('404 handler returns structured format', async () => {
    // Test the default Hono 404 path (not in test app, but verify format convention)
    const mainApp = new Hono();
    mainApp.notFound((c) =>
      c.json({ error: { code: 'NOT_FOUND', message: `Route not found: ${c.req.method} ${c.req.path}` } }, 404)
    );

    const res = await mainApp.request('/nonexistent');
    expect(res.status).toBe(404);

    const body: ErrorBody = await res.json();
    expect(body.error.code).toBe('NOT_FOUND');
    expect(body.error.message).toContain('/nonexistent');
  });
});
