/**
 * Cross-tenant data isolation tests.
 *
 * Verifies that users in Org A cannot access data belonging to Org B,
 * and that platform_admin users CAN access cross-org data.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../index';
import { assets } from './assets';
import { findings } from './findings';
import { scans } from './scans';
import { errorHandler } from '../middleware/error-handler';
import { orgScopeMiddleware } from '../middleware/org-scope';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const ORG_A = 'org-aaa';
const ORG_B = 'org-bbb';

function createTestAppWithOrgScope(
  route: Hono<{ Bindings: Env }>,
  prefix: string,
  db: any,
  userOverrides: Record<string, unknown> = {},
) {
  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    (c.env as any) = {
      DB: db,
      STORAGE: { put: vi.fn(), get: vi.fn(), delete: vi.fn() },
      CACHE: { put: vi.fn(), get: vi.fn().mockResolvedValue(null), delete: vi.fn() },
    };
    // Inject authenticated user with org context
    c.set('user' as any, {
      id: 'user-001',
      email: 'test@example.com',
      role: 'scan_admin',
      display_name: 'Test User',
      organization_id: ORG_A,
      org_role: 'admin',
      ...userOverrides,
    });
    await next();
  });
  app.use('*', orgScopeMiddleware);
  app.route(prefix, route);
  app.onError(errorHandler);
  return app;
}

function createMockDBWithOrgData() {
  // Track queries to verify org_id filtering
  const queries: { sql: string; params: any[] }[] = [];

  const mockAll = vi.fn().mockResolvedValue({ results: [] });
  const mockFirst = vi.fn().mockResolvedValue(null);
  const mockRun = vi.fn().mockResolvedValue({ success: true, meta: { changes: 1 } });

  const bindResult = {
    run: mockRun,
    first: mockFirst,
    all: mockAll,
  };

  const db = {
    prepare: vi.fn().mockImplementation((sql: string) => {
      return {
        bind: vi.fn().mockImplementation((...params: any[]) => {
          queries.push({ sql, params });
          return bindResult;
        }),
        run: mockRun,
        first: mockFirst,
        all: mockAll,
      };
    }),
    _queries: queries,
    _mockAll: mockAll,
    _mockFirst: mockFirst,
    _mockRun: mockRun,
  };

  return db;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Cross-Tenant Data Isolation', () => {
  describe('Assets', () => {
    it('should include org_id filter in list query for scoped user', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(assets, '/assets', db);

      const res = await app.request('/assets');
      expect(res.status).toBe(200);

      // Check that at least one query included org_id binding
      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.params.includes(ORG_A)
      );
      expect(orgFilteredQueries.length).toBeGreaterThan(0);
    });

    it('should include org_id filter in get-by-id query for scoped user', async () => {
      const db = createMockDBWithOrgData();
      db._mockFirst.mockResolvedValue({
        id: 'asset-001',
        hostname: 'web-01',
        org_id: ORG_A,
      });
      const app = createTestAppWithOrgScope(assets, '/assets', db);

      const res = await app.request('/assets/asset-001');
      expect(res.status).toBe(200);

      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.params.includes(ORG_A) && q.params.includes('asset-001')
      );
      expect(orgFilteredQueries.length).toBeGreaterThan(0);
    });

    it('should return 404 when user tries to access asset from different org', async () => {
      const db = createMockDBWithOrgData();
      // DB returns null because org_id filter excludes the record
      db._mockFirst.mockResolvedValue(null);
      const app = createTestAppWithOrgScope(assets, '/assets', db);

      const res = await app.request('/assets/asset-from-org-b');
      expect(res.status).toBe(404);
    });

    it('should include org_id in create asset', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(assets, '/assets', db);

      const res = await app.request('/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: 'new-host', asset_type: 'server' }),
      });

      expect(res.status).toBe(201);

      // Verify INSERT included org_id
      const insertQueries = db._queries.filter(
        (q: any) => q.sql.includes('INSERT') && q.params.includes(ORG_A)
      );
      expect(insertQueries.length).toBeGreaterThan(0);
    });
  });

  describe('Findings', () => {
    it('should include org_id filter in list query', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(findings, '/findings', db);

      const res = await app.request('/findings');
      expect(res.status).toBe(200);

      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.params.includes(ORG_A)
      );
      expect(orgFilteredQueries.length).toBeGreaterThan(0);
    });
  });

  describe('Scans', () => {
    it('should include org_id filter in list query', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(scans, '/scans', db);

      const res = await app.request('/scans');
      expect(res.status).toBe(200);

      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.params.includes(ORG_A)
      );
      expect(orgFilteredQueries.length).toBeGreaterThan(0);
    });

    it('should include org_id in create scan', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(scans, '/scans', db);

      const res = await app.request('/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Test Scan', type: 'network', target: '10.0.0.0/24' }),
      });

      expect(res.status).toBe(201);

      const insertQueries = db._queries.filter(
        (q: any) => q.sql.includes('INSERT') && q.params.includes(ORG_A)
      );
      expect(insertQueries.length).toBeGreaterThan(0);
    });
  });

  describe('Platform Admin Access', () => {
    it('should NOT include org_id filter for platform_admin without X-Organization-Id', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(assets, '/assets', db, {
        role: 'platform_admin',
        organization_id: null,
        org_role: null,
      });

      const res = await app.request('/assets');
      expect(res.status).toBe(200);

      // Admin without org scope should NOT filter by org_id
      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.sql.includes('org_id')
      );
      expect(orgFilteredQueries.length).toBe(0);
    });

    it('should include org_id filter for platform_admin WITH organization_id set', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(assets, '/assets', db, {
        role: 'platform_admin',
        organization_id: ORG_B,
        org_role: 'owner',
      });

      const res = await app.request('/assets');
      expect(res.status).toBe(200);

      const orgFilteredQueries = db._queries.filter(
        (q: any) => q.params.includes(ORG_B)
      );
      expect(orgFilteredQueries.length).toBeGreaterThan(0);
    });
  });

  describe('Org Scope Middleware', () => {
    it('should return 403 for user with no organization membership', async () => {
      const db = createMockDBWithOrgData();
      const app = createTestAppWithOrgScope(assets, '/assets', db, {
        role: 'auditor',
        organization_id: null,
        org_role: null,
      });

      const res = await app.request('/assets');
      expect(res.status).toBe(403);

      const body = await res.json();
      expect(body.error).toBe('Forbidden');
    });
  });
});
