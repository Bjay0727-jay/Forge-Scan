import { describe, it, expect } from 'vitest';
import { ApiError } from './errors';
import {
  requireField,
  requireEnum,
  parsePagination,
  parsePositiveInt,
  validateSort,
  validateSortOrder,
} from './validate';

describe('requireField', () => {
  it('passes for truthy values', () => {
    expect(() => requireField('hello', 'name')).not.toThrow();
    expect(() => requireField(42, 'count')).not.toThrow();
    expect(() => requireField(true, 'flag')).not.toThrow();
  });

  it('throws MISSING_FIELD for undefined', () => {
    expect(() => requireField(undefined, 'email')).toThrow(ApiError);
    try {
      requireField(undefined, 'email');
    } catch (e) {
      const err = e as ApiError;
      expect(err.code).toBe('MISSING_FIELD');
      expect(err.status).toBe(400);
      expect(err.message).toContain('email');
    }
  });

  it('throws MISSING_FIELD for null', () => {
    expect(() => requireField(null, 'x')).toThrow(ApiError);
  });

  it('throws MISSING_FIELD for empty string', () => {
    expect(() => requireField('', 'name')).toThrow(ApiError);
  });
});

describe('requireEnum', () => {
  const allowed = ['open', 'closed', 'pending'] as const;

  it('returns the value when valid', () => {
    expect(requireEnum('open', 'status', allowed)).toBe('open');
    expect(requireEnum('closed', 'status', allowed)).toBe('closed');
  });

  it('throws INVALID_ENUM for invalid value', () => {
    expect(() => requireEnum('invalid', 'status', allowed)).toThrow(ApiError);
    try {
      requireEnum('invalid', 'status', allowed);
    } catch (e) {
      const err = e as ApiError;
      expect(err.code).toBe('INVALID_ENUM');
      expect(err.details?.allowed).toEqual(['open', 'closed', 'pending']);
    }
  });

  it('throws INVALID_ENUM for undefined', () => {
    expect(() => requireEnum(undefined, 'status', allowed)).toThrow(ApiError);
  });
});

describe('parsePagination', () => {
  it('returns defaults when no params provided', () => {
    const result = parsePagination();
    expect(result).toEqual({ page: 1, pageSize: 20, offset: 0 });
  });

  it('parses string page and page_size', () => {
    const result = parsePagination('3', '10');
    expect(result).toEqual({ page: 3, pageSize: 10, offset: 20 });
  });

  it('clamps page_size to maxPageSize', () => {
    const result = parsePagination('1', '500');
    expect(result.pageSize).toBe(100);
  });

  it('throws for negative page', () => {
    expect(() => parsePagination('-1', '20')).toThrow(ApiError);
    try {
      parsePagination('-1', '20');
    } catch (e) {
      expect((e as ApiError).code).toBe('INVALID_PAGINATION');
    }
  });

  it('throws for page = 0', () => {
    expect(() => parsePagination('0', '20')).toThrow(ApiError);
  });

  it('throws for non-numeric page', () => {
    expect(() => parsePagination('abc', '20')).toThrow(ApiError);
  });

  it('throws for non-numeric page_size', () => {
    expect(() => parsePagination('1', 'xyz')).toThrow(ApiError);
  });

  it('computes correct offset', () => {
    expect(parsePagination('1', '25').offset).toBe(0);
    expect(parsePagination('2', '25').offset).toBe(25);
    expect(parsePagination('5', '10').offset).toBe(40);
  });

  it('respects custom defaults', () => {
    const result = parsePagination(undefined, undefined, { page: 1, pageSize: 50, maxPageSize: 200 });
    expect(result.pageSize).toBe(50);
  });
});

describe('parsePositiveInt', () => {
  it('returns parsed int for valid string', () => {
    expect(parsePositiveInt('42', 10)).toBe(42);
  });

  it('returns default for undefined', () => {
    expect(parsePositiveInt(undefined, 10)).toBe(10);
  });

  it('throws for non-numeric strings', () => {
    expect(() => parsePositiveInt('abc', 10)).toThrow(ApiError);
  });

  it('throws for zero', () => {
    expect(() => parsePositiveInt('0', 10)).toThrow(ApiError);
  });

  it('throws for negative numbers', () => {
    expect(() => parsePositiveInt('-5', 10)).toThrow(ApiError);
  });
});

describe('validateSort', () => {
  const allowed = ['name', 'date', 'score'] as const;

  it('returns the field when valid', () => {
    expect(validateSort('name', allowed, 'date')).toBe('name');
  });

  it('returns default for invalid field', () => {
    expect(validateSort('invalid', allowed, 'date')).toBe('date');
  });

  it('returns default for undefined', () => {
    expect(validateSort(undefined, allowed, 'date')).toBe('date');
  });
});

describe('validateSortOrder', () => {
  it('returns ASC for "asc"', () => {
    expect(validateSortOrder('asc')).toBe('ASC');
  });

  it('returns ASC for "ASC"', () => {
    expect(validateSortOrder('ASC')).toBe('ASC');
  });

  it('returns DESC for "desc"', () => {
    expect(validateSortOrder('desc')).toBe('DESC');
  });

  it('returns DESC for undefined (default)', () => {
    expect(validateSortOrder(undefined)).toBe('DESC');
  });

  it('returns DESC for unknown values', () => {
    expect(validateSortOrder('bogus')).toBe('DESC');
  });
});
