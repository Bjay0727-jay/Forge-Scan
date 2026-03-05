/**
 * Zod request body schemas for API endpoints.
 * Used by route handlers to validate incoming payloads at the boundary.
 */
import { z } from 'zod';

// ─── Shared ──────────────────────────────────────────────────────────────────

const severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);

// ─── Assets ──────────────────────────────────────────────────────────────────

export const createAssetSchema = z.object({
  hostname: z.string().max(255).nullish(),
  fqdn: z.string().max(255).nullish(),
  ip_addresses: z.array(z.string().max(45)).max(50).default([]),
  mac_addresses: z.array(z.string().max(17)).max(50).default([]),
  os: z.string().max(100).nullish(),
  os_version: z.string().max(50).nullish(),
  asset_type: z.string().max(50).default('unknown'),
  network_zone: z.string().max(50).nullish(),
  tags: z.array(z.string().max(100)).max(50).default([]),
  attributes: z.record(z.unknown()).default({}),
}).refine(
  (d) => d.hostname || d.fqdn || d.ip_addresses.length > 0,
  { message: 'At least one of hostname, fqdn, or ip_addresses is required' },
);

export const updateAssetSchema = z.object({
  hostname: z.string().max(255).nullish(),
  fqdn: z.string().max(255).nullish(),
  ip_addresses: z.array(z.string().max(45)).max(50).optional(),
  mac_addresses: z.array(z.string().max(17)).max(50).optional(),
  os: z.string().max(100).nullish(),
  os_version: z.string().max(50).nullish(),
  asset_type: z.string().max(50).optional(),
  network_zone: z.string().max(50).nullish(),
  tags: z.array(z.string().max(100)).max(50).optional(),
  attributes: z.record(z.unknown()).optional(),
});

// ─── Findings ────────────────────────────────────────────────────────────────

export const createFindingSchema = z.object({
  asset_id: z.string().min(1).max(255),
  vulnerability_id: z.string().max(255).nullish(),
  vendor: z.string().max(100),
  vendor_id: z.string().max(255),
  title: z.string().max(500),
  description: z.string().max(10000).nullish(),
  severity,
  frs_score: z.number().min(0).max(10).nullish(),
  port: z.number().int().min(0).max(65535).nullish(),
  protocol: z.string().max(20).nullish(),
  service: z.string().max(100).nullish(),
  state: z.enum(['open', 'closed', 'accepted', 'false_positive']).default('open'),
  solution: z.string().max(10000).nullish(),
  evidence: z.string().max(50000).nullish(),
  metadata: z.record(z.unknown()).default({}),
});

// ─── Scans ───────────────────────────────────────────────────────────────────

export const createScanSchema = z.object({
  name: z.string().min(1).max(200),
  type: z.string().max(50).optional(),
  scan_type: z.string().max(50).optional(),
  target: z.union([z.string(), z.array(z.string())]).optional(),
  targets: z.union([z.string(), z.array(z.string())]).optional(),
  config: z.record(z.unknown()).optional(),
  configuration: z.record(z.unknown()).optional(),
}).refine(
  (d) => d.type || d.scan_type,
  { message: 'type or scan_type is required' },
).refine(
  (d) => d.target || d.targets,
  { message: 'target or targets is required' },
);

// ─── Auth ────────────────────────────────────────────────────────────────────

export const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(128),
});

export const registerSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
  display_name: z.string().min(1).max(100),
  role: z.string().max(50).optional(),
});

// ─── Validation helper ──────────────────────────────────────────────────────

import { badRequest } from './errors';

/**
 * Parse and validate request body against a Zod schema.
 * Throws a 400 ApiError with structured field errors on failure.
 */
export function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body);
  if (!result.success) {
    const fieldErrors = result.error.issues.map((i) => ({
      field: i.path.join('.'),
      message: i.message,
    }));
    throw badRequest(`Validation failed: ${fieldErrors.map((e) => e.message).join('; ')}`);
  }
  return result.data;
}
