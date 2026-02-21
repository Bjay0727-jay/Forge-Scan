import { describe, it, expect } from 'vitest';
import {
  ApiError,
  ErrorCode,
  badRequest,
  missingField,
  invalidEnum,
  invalidPagination,
  notFound,
  conflict,
  invalidStateTransition,
  internalError,
  databaseError,
} from './errors';

describe('ApiError', () => {
  it('stores status, code, message, and details', () => {
    const err = new ApiError(400, ErrorCode.VALIDATION_ERROR, 'bad input', { field: 'name' });
    expect(err.status).toBe(400);
    expect(err.code).toBe('VALIDATION_ERROR');
    expect(err.message).toBe('bad input');
    expect(err.details).toEqual({ field: 'name' });
    expect(err.name).toBe('ApiError');
  });

  it('serialises to structured JSON', () => {
    const err = new ApiError(404, ErrorCode.NOT_FOUND, 'not found');
    expect(err.toJSON()).toEqual({
      error: {
        code: 'NOT_FOUND',
        message: 'not found',
      },
    });
  });

  it('includes details in JSON when present', () => {
    const err = new ApiError(400, ErrorCode.MISSING_FIELD, 'Missing field', { field: 'email' });
    const json = err.toJSON();
    expect(json.error.details).toEqual({ field: 'email' });
  });

  it('omits details from JSON when absent', () => {
    const err = new ApiError(500, ErrorCode.INTERNAL_ERROR, 'oops');
    const json = err.toJSON();
    expect(json.error).not.toHaveProperty('details');
  });

  it('extends Error and has correct instanceof chain', () => {
    const err = new ApiError(400, ErrorCode.VALIDATION_ERROR, 'bad');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ApiError);
  });
});

describe('error factories', () => {
  describe('badRequest', () => {
    it('creates a 400 VALIDATION_ERROR', () => {
      const err = badRequest('invalid data');
      expect(err.status).toBe(400);
      expect(err.code).toBe('VALIDATION_ERROR');
      expect(err.message).toBe('invalid data');
    });

    it('accepts optional details', () => {
      const err = badRequest('bad', { field: 'x' });
      expect(err.details).toEqual({ field: 'x' });
    });
  });

  describe('missingField', () => {
    it('creates a 400 MISSING_FIELD with field name', () => {
      const err = missingField('email');
      expect(err.status).toBe(400);
      expect(err.code).toBe('MISSING_FIELD');
      expect(err.message).toContain('email');
      expect(err.details?.field).toBe('email');
    });
  });

  describe('invalidEnum', () => {
    it('lists allowed values in message', () => {
      const err = invalidEnum('status', 'bogus', ['open', 'closed']);
      expect(err.status).toBe(400);
      expect(err.code).toBe('INVALID_ENUM');
      expect(err.message).toContain('bogus');
      expect(err.message).toContain('open, closed');
      expect(err.details?.allowed).toEqual(['open', 'closed']);
    });
  });

  describe('invalidPagination', () => {
    it('creates a 400 INVALID_PAGINATION', () => {
      const err = invalidPagination('page must be positive');
      expect(err.status).toBe(400);
      expect(err.code).toBe('INVALID_PAGINATION');
    });
  });

  describe('notFound', () => {
    it('returns resource-specific codes', () => {
      expect(notFound('Asset', '123').code).toBe('ASSET_NOT_FOUND');
      expect(notFound('Finding').code).toBe('FINDING_NOT_FOUND');
      expect(notFound('Scan', 'abc').code).toBe('SCAN_NOT_FOUND');
      expect(notFound('Report').code).toBe('REPORT_NOT_FOUND');
      expect(notFound('Schedule').code).toBe('SCHEDULE_NOT_FOUND');
      expect(notFound('Job').code).toBe('JOB_NOT_FOUND');
      expect(notFound('Rule').code).toBe('RULE_NOT_FOUND');
      expect(notFound('Integration').code).toBe('INTEGRATION_NOT_FOUND');
    });

    it('falls back to generic NOT_FOUND for unknown resources', () => {
      expect(notFound('Widget').code).toBe('NOT_FOUND');
    });

    it('includes resource ID in message when provided', () => {
      const err = notFound('Asset', 'abc-123');
      expect(err.message).toBe('Asset not found: abc-123');
    });

    it('omits ID when not provided', () => {
      const err = notFound('Asset');
      expect(err.message).toBe('Asset not found');
    });

    it('always returns 404', () => {
      expect(notFound('Asset').status).toBe(404);
      expect(notFound('Widget').status).toBe(404);
    });
  });

  describe('conflict', () => {
    it('creates a 409 CONFLICT', () => {
      const err = conflict('Already exists');
      expect(err.status).toBe(409);
      expect(err.code).toBe('CONFLICT');
    });
  });

  describe('invalidStateTransition', () => {
    it('creates a 409 with current and attempted states', () => {
      const err = invalidStateTransition('completed', 'running');
      expect(err.status).toBe(409);
      expect(err.code).toBe('INVALID_STATE_TRANSITION');
      expect(err.message).toContain('completed');
      expect(err.message).toContain('running');
    });
  });

  describe('internalError', () => {
    it('creates a 500 with default message', () => {
      const err = internalError();
      expect(err.status).toBe(500);
      expect(err.code).toBe('INTERNAL_ERROR');
      expect(err.message).toBe('An internal error occurred');
    });

    it('accepts custom message', () => {
      const err = internalError('something broke');
      expect(err.message).toBe('something broke');
    });
  });

  describe('databaseError', () => {
    it('masks UNIQUE constraint errors', () => {
      const err = databaseError(new Error('UNIQUE constraint failed: users.email'));
      expect(err.status).toBe(500);
      expect(err.code).toBe('DATABASE_ERROR');
      expect(err.message).toContain('already exists');
      expect(err.message).not.toContain('UNIQUE');
    });

    it('masks FOREIGN KEY constraint errors', () => {
      const err = databaseError(new Error('FOREIGN KEY constraint failed'));
      expect(err.message).toContain('does not exist');
    });

    it('masks NOT NULL constraint errors', () => {
      const err = databaseError(new Error('NOT NULL constraint failed: findings.title'));
      expect(err.message).toContain('required field');
      expect(err.message).not.toContain('findings.title');
    });

    it('returns generic message for unknown DB errors', () => {
      const err = databaseError(new Error('table locked'));
      expect(err.message).toBe('A database error occurred');
    });

    it('handles non-Error values', () => {
      const err = databaseError('some string error');
      expect(err.status).toBe(500);
      expect(err.code).toBe('DATABASE_ERROR');
    });
  });
});
