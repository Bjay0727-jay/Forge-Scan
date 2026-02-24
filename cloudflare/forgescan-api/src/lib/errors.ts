/**
 * Structured error types for the ForgeScan API.
 *
 * Each error carries an HTTP status, machine-readable code, and human-readable
 * message so that every route can throw and the global handler will format a
 * consistent JSON response.
 */

// ─── Error codes (machine-readable, stable across versions) ──────────────────
export const ErrorCode = {
  // 400 – Bad Request family
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
  MISSING_FIELD: 'MISSING_FIELD',
  INVALID_FORMAT: 'INVALID_FORMAT',
  INVALID_ENUM: 'INVALID_ENUM',
  INVALID_PAGINATION: 'INVALID_PAGINATION',

  // 401 / 403
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',

  // 404
  NOT_FOUND: 'NOT_FOUND',
  ASSET_NOT_FOUND: 'ASSET_NOT_FOUND',
  FINDING_NOT_FOUND: 'FINDING_NOT_FOUND',
  SCAN_NOT_FOUND: 'SCAN_NOT_FOUND',
  REPORT_NOT_FOUND: 'REPORT_NOT_FOUND',
  SCHEDULE_NOT_FOUND: 'SCHEDULE_NOT_FOUND',
  JOB_NOT_FOUND: 'JOB_NOT_FOUND',
  RULE_NOT_FOUND: 'RULE_NOT_FOUND',
  INTEGRATION_NOT_FOUND: 'INTEGRATION_NOT_FOUND',

  // 409 – Conflict
  CONFLICT: 'CONFLICT',
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  INVALID_STATE_TRANSITION: 'INVALID_STATE_TRANSITION',

  // 429 – Rate Limited
  RATE_LIMITED: 'RATE_LIMITED',

  // 500 – Internal
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  STORAGE_ERROR: 'STORAGE_ERROR',
  IMPORT_ERROR: 'IMPORT_ERROR',
  REPORT_GENERATION_ERROR: 'REPORT_GENERATION_ERROR',
} as const;

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode];

// ─── Base API error ──────────────────────────────────────────────────────────
export class ApiError extends Error {
  public readonly status: number;
  public readonly code: ErrorCodeType;
  public readonly details?: Record<string, unknown>;

  constructor(
    status: number,
    code: ErrorCodeType,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }

  /** Serialise to the shape every API response uses. */
  toJSON() {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }
}

// ─── Convenience factories ───────────────────────────────────────────────────

/** 400 – generic bad request */
export function badRequest(message: string, details?: Record<string, unknown>) {
  return new ApiError(400, ErrorCode.VALIDATION_ERROR, message, details);
}

/** 400 – missing required field */
export function missingField(field: string) {
  return new ApiError(400, ErrorCode.MISSING_FIELD, `Missing required field: ${field}`, { field });
}

/** 400 – value not in allowed set */
export function invalidEnum(field: string, value: unknown, allowed: readonly string[]) {
  return new ApiError(400, ErrorCode.INVALID_ENUM, `Invalid value for ${field}: '${value}'. Allowed: ${allowed.join(', ')}`, {
    field,
    value,
    allowed,
  });
}

/** 400 – pagination out of range */
export function invalidPagination(message: string) {
  return new ApiError(400, ErrorCode.INVALID_PAGINATION, message);
}

/** 404 – resource not found */
export function notFound(resource: string, id?: string) {
  const codeMap: Record<string, ErrorCodeType> = {
    asset: ErrorCode.ASSET_NOT_FOUND,
    finding: ErrorCode.FINDING_NOT_FOUND,
    scan: ErrorCode.SCAN_NOT_FOUND,
    report: ErrorCode.REPORT_NOT_FOUND,
    schedule: ErrorCode.SCHEDULE_NOT_FOUND,
    job: ErrorCode.JOB_NOT_FOUND,
    rule: ErrorCode.RULE_NOT_FOUND,
    integration: ErrorCode.INTEGRATION_NOT_FOUND,
  };

  const code = codeMap[resource.toLowerCase()] || ErrorCode.NOT_FOUND;
  const msg = id ? `${resource} not found: ${id}` : `${resource} not found`;
  return new ApiError(404, code, msg);
}

/** 409 – conflict / duplicate */
export function conflict(message: string) {
  return new ApiError(409, ErrorCode.CONFLICT, message);
}

/** 409 – invalid state transition */
export function invalidStateTransition(current: string, attempted: string) {
  return new ApiError(409, ErrorCode.INVALID_STATE_TRANSITION, `Cannot transition from '${current}' to '${attempted}'`);
}

/** 429 – rate limited */
export function rateLimited(retryAfter?: number) {
  return new ApiError(429, ErrorCode.RATE_LIMITED, 'Too many requests. Please try again later.', retryAfter ? { retry_after: retryAfter } : undefined);
}

/** 500 – internal / database error */
export function internalError(message = 'An internal error occurred') {
  return new ApiError(500, ErrorCode.INTERNAL_ERROR, message);
}

/** 500 – database-specific error (strips raw SQL details in production) */
export function databaseError(err: unknown) {
  const raw = err instanceof Error ? err.message : String(err);
  // Never leak full SQL errors to the client
  const safeMessage = raw.includes('UNIQUE constraint')
    ? 'A record with this identifier already exists'
    : raw.includes('FOREIGN KEY constraint')
      ? 'Referenced record does not exist'
      : raw.includes('NOT NULL constraint')
        ? 'A required field was missing'
        : 'A database error occurred';
  return new ApiError(500, ErrorCode.DATABASE_ERROR, safeMessage);
}
