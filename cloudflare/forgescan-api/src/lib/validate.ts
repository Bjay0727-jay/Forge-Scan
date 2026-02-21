/**
 * Lightweight input validation helpers.
 *
 * Each function throws an `ApiError` on invalid input so route handlers can
 * stay concise — the global error handler will catch and format the response.
 */
import { badRequest, invalidEnum, invalidPagination, missingField } from './errors';

/** Require a field to be present and non-empty. */
export function requireField(value: unknown, name: string): asserts value {
  if (value === undefined || value === null || value === '') {
    throw missingField(name);
  }
}

/** Require a string to be one of the allowed values. */
export function requireEnum<T extends string>(value: string | undefined, name: string, allowed: readonly T[]): T {
  if (!value || !allowed.includes(value as T)) {
    throw invalidEnum(name, value, allowed);
  }
  return value as T;
}

/** Parse and validate pagination parameters. Returns clamped values. */
export function parsePagination(
  page?: string,
  pageSize?: string,
  defaults = { page: 1, pageSize: 20, maxPageSize: 100 },
) {
  const p = page ? parseInt(page, 10) : defaults.page;
  const ps = pageSize ? parseInt(pageSize, 10) : defaults.pageSize;

  if (isNaN(p) || p < 1) {
    throw invalidPagination('page must be a positive integer');
  }
  if (isNaN(ps) || ps < 1) {
    throw invalidPagination('page_size must be a positive integer');
  }

  const clampedSize = Math.min(ps, defaults.maxPageSize);
  const offset = (p - 1) * clampedSize;

  return { page: p, pageSize: clampedSize, offset };
}

/** Parse a positive integer from a string, with a fallback default. */
export function parsePositiveInt(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const n = parseInt(value, 10);
  if (isNaN(n) || n < 1) {
    throw badRequest(`Expected a positive integer, got '${value}'`);
  }
  return n;
}

/** Validate sort field against allowed list, fallback to default. */
export function validateSort(sortBy: string | undefined, allowed: readonly string[], defaultField: string) {
  return allowed.includes(sortBy || '') ? (sortBy as string) : defaultField;
}

/** Validate sort direction. */
export function validateSortOrder(order: string | undefined): 'ASC' | 'DESC' {
  return order?.toLowerCase() === 'asc' ? 'ASC' : 'DESC';
}
