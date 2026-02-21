/**
 * Shared test helpers for ForgeScan API route integration tests.
 *
 * Provides mock D1 database, mock environment, and app creation helpers
 * so each test file can focus on endpoint-specific assertions.
 */

import { vi } from 'vitest';
import { Hono } from 'hono';
import type { Env } from './index';
import { errorHandler } from './middleware/error-handler';

// ─── D1 Mock ────────────────────────────────────────────────────────────────

export interface MockDBOptions {
  allResults?: any[];
  firstResult?: any;
  runSuccess?: boolean;
  shouldFail?: boolean;
  failMessage?: string;
}

export function createMockDB(options: MockDBOptions = {}) {
  const {
    allResults = [],
    firstResult = null,
    runSuccess = true,
    shouldFail = false,
    failMessage = 'DB error',
  } = options;

  const mockRun = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue({ success: runSuccess, meta: { changes: allResults.length || 1 } });

  const mockFirst = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue(firstResult);

  const mockAll = shouldFail
    ? vi.fn().mockRejectedValue(new Error(failMessage))
    : vi.fn().mockResolvedValue({ results: allResults });

  const bindResult = {
    run: mockRun,
    first: mockFirst,
    all: mockAll,
  };

  return {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue(bindResult),
      // Support prepare().all() / prepare().first() without bind()
      run: mockRun,
      first: mockFirst,
      all: mockAll,
    }),
    _mockRun: mockRun,
    _mockFirst: mockFirst,
    _mockAll: mockAll,
  };
}

/**
 * Create a mock DB that returns different results for sequential calls.
 * Pass an array of MockDBOptions — each call to first/all/run uses the next entry.
 */
export function createSequentialMockDB(sequence: MockDBOptions[]) {
  let callIndex = 0;

  const getNext = () => {
    const opts = sequence[Math.min(callIndex, sequence.length - 1)];
    callIndex++;
    return opts;
  };

  return {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue({
        run: vi.fn().mockImplementation(() => {
          const opts = getNext();
          if (opts.shouldFail) return Promise.reject(new Error(opts.failMessage || 'DB error'));
          return Promise.resolve({ success: opts.runSuccess ?? true, meta: { changes: 1 } });
        }),
        first: vi.fn().mockImplementation(() => {
          const opts = getNext();
          if (opts.shouldFail) return Promise.reject(new Error(opts.failMessage || 'DB error'));
          return Promise.resolve(opts.firstResult ?? null);
        }),
        all: vi.fn().mockImplementation(() => {
          const opts = getNext();
          if (opts.shouldFail) return Promise.reject(new Error(opts.failMessage || 'DB error'));
          return Promise.resolve({ results: opts.allResults ?? [] });
        }),
      }),
    }),
    _callIndex: () => callIndex,
  };
}

// ─── App Factory ──────────────────────────────────────────────────────────────

export function createTestApp(
  route: Hono<{ Bindings: Env }>,
  prefix: string,
  db?: any,
) {
  const app = new Hono<{ Bindings: Env }>();
  // Auth bypass middleware — injects mock env
  app.use('*', async (c, next) => {
    (c.env as any) = {
      DB: db || createMockDB(),
      STORAGE: { put: vi.fn(), get: vi.fn(), delete: vi.fn() },
      CACHE: { put: vi.fn(), get: vi.fn().mockResolvedValue(null), delete: vi.fn() },
    };
    await next();
  });
  app.route(prefix, route);
  app.onError(errorHandler);
  return app;
}

// ─── Test Data Factories ──────────────────────────────────────────────────────

export function mockFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: 'finding-001',
    asset_id: 'asset-001',
    scan_id: 'scan-001',
    vulnerability_id: null,
    vendor: 'generic',
    vendor_id: 'VULN-001',
    title: 'SQL Injection',
    description: 'Parameterized queries not used',
    severity: 'critical',
    state: 'open',
    frs_score: 9.5,
    port: 443,
    protocol: 'tcp',
    service: 'https',
    cve_id: 'CVE-2024-1234',
    cvss_score: 9.8,
    solution: 'Use parameterized queries',
    evidence: null,
    references: '[]',
    first_seen: '2024-01-01T00:00:00Z',
    last_seen: '2024-01-15T00:00:00Z',
    fixed_at: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
    ...overrides,
  };
}

export function mockAsset(overrides: Record<string, unknown> = {}) {
  return {
    id: 'asset-001',
    hostname: 'web-01',
    fqdn: 'web-01.example.com',
    ip_addresses: '["10.0.0.1"]',
    mac_addresses: '[]',
    os: 'Ubuntu',
    os_version: '22.04',
    asset_type: 'server',
    network_zone: 'dmz',
    risk_score: 85,
    tags: '["production"]',
    attributes: '{}',
    first_seen: '2024-01-01T00:00:00Z',
    last_seen: '2024-01-15T00:00:00Z',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
    ...overrides,
  };
}

export function mockScan(overrides: Record<string, unknown> = {}) {
  return {
    id: 'scan-001',
    name: 'Network Scan Q1',
    scan_type: 'network',
    targets: '["10.0.0.0/24"]',
    config: '{}',
    status: 'pending',
    findings_count: 0,
    assets_count: 0,
    started_at: null,
    completed_at: null,
    error_message: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

export function mockCampaign(overrides: Record<string, unknown> = {}) {
  return {
    id: 'campaign-001',
    name: 'Q1 Pen Test',
    description: 'Quarterly penetration test',
    status: 'created',
    campaign_type: 'full',
    target_scope: '["10.0.0.0/24"]',
    exclusions: null,
    agent_categories: '["web","api","network"]',
    max_concurrent_agents: 6,
    exploitation_level: 'safe',
    risk_threshold: 'critical',
    auto_poam: 0,
    compliance_mapping: 1,
    findings_count: 0,
    exploitable_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    total_agents: 0,
    completed_agents: 0,
    progress: 0,
    scheduled_at: null,
    started_at: null,
    completed_at: null,
    created_by: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}

export function mockRedOpsFinding(overrides: Record<string, unknown> = {}) {
  return {
    id: 'redops-finding-001',
    campaign_id: 'campaign-001',
    agent_id: 'agent-001',
    title: 'SQL Injection in Login Form',
    description: 'The login form is vulnerable to SQL injection',
    severity: 'critical',
    exploitable: 1,
    status: 'confirmed',
    attack_vector: 'POST /login username parameter',
    cwe_id: 'CWE-89',
    cve_id: null,
    mitre_technique: 'T1190',
    exploitation_proof: 'Successfully extracted database schema',
    remediation: 'Use parameterized queries',
    remediation_effort: 'low',
    nist_controls: '["SI-10","SC-18"]',
    affected_component: '/login',
    target_host: '10.0.0.1',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
    ...overrides,
  };
}
